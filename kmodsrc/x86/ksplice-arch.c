/*  Copyright (C) 2007-2008  Jeffrey Brian Arnold <jbarnold@mit.edu>
 *  Copyright (C) 2008  Anders Kaseorg <andersk@mit.edu>,
 *                      Tim Abbott <tabbott@mit.edu>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#ifdef __ASM_X86_PROCESSOR_H	/* New unified x86 */
#define KSPLICE_IP(x) ((x)->thread.ip)
#define KSPLICE_SP(x) ((x)->thread.sp)
#elif defined(CONFIG_X86_64)	/* Old x86 64-bit */
/* The IP is on the stack, so we don't need to check it separately.
 * Instead, we need to prevent Ksplice from patching thread_return.
 */
extern const char thread_return[];
#define KSPLICE_IP(x) ((unsigned long)thread_return)
#define KSPLICE_SP(x) ((x)->thread.rsp)
#else /* Old x86 32-bit */
#define KSPLICE_IP(x) ((x)->thread.eip)
#define KSPLICE_SP(x) ((x)->thread.esp)
#endif /* __ASM_X86_PROCESSOR_H */

#ifndef CONFIG_FUNCTION_DATA_SECTIONS
#include "udis86.h"

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

static abort_t compare_operands(struct ksplice_pack *pack,
				const struct ksplice_size *s,
				unsigned long *match_map,
				unsigned long run_addr,
				const unsigned char *run,
				const unsigned char *pre, struct ud *run_ud,
				struct ud *pre_ud, int opnum,
				enum run_pre_mode mode);
static int match_nop(const unsigned char *addr);
static uint8_t ud_operand_len(struct ud_operand *operand);
static uint8_t ud_prefix_len(struct ud *ud);
static long jump_lval(struct ud_operand *operand);
static int next_run_byte(struct ud *ud);

static abort_t arch_run_pre_cmp(struct ksplice_pack *pack,
				const struct ksplice_size *s,
				unsigned long run_addr,
				struct list_head *safety_records,
				enum run_pre_mode mode)
{
	int runc, prec;
	int i;
	abort_t ret;
	const unsigned char *run, *pre;
	struct ud pre_ud, run_ud;
	unsigned long run_start, pre_addr = s->thismod_addr;

	unsigned long *match_map;

	if (s->size == 0)
		return NO_MATCH;

	run_addr = follow_trampolines(pack, run_addr);

	run = (const unsigned char *)run_addr;
	pre = (const unsigned char *)pre_addr;

	ud_init(&pre_ud);
	ud_set_mode(&pre_ud, BITS_PER_LONG);
	ud_set_syntax(&pre_ud, UD_SYN_ATT);
	ud_set_input_buffer(&pre_ud, (unsigned char *)pre, s->size);
	ud_set_pc(&pre_ud, 0);

	ud_init(&run_ud);
	ud_set_mode(&run_ud, BITS_PER_LONG);
	ud_set_syntax(&run_ud, UD_SYN_ATT);
	ud_set_input_hook(&run_ud, next_run_byte);
	ud_set_pc(&run_ud, 0);
	run_ud.userdata = (unsigned char *)run_addr;
	run_start = run_addr;

	match_map = vmalloc(sizeof(*match_map) * s->size);
	if (match_map == NULL)
		return OUT_OF_MEMORY;
	memset(match_map, 0, sizeof(*match_map) * s->size);
	match_map[0] = run_addr;

	while (1) {
		if (ud_disassemble(&pre_ud) == 0) {
			/* Ran out of pre bytes to match; we're done! */
			ret = create_safety_record(pack, s, safety_records,
						   run_start,
						   (unsigned long)run -
						   run_start);
			goto out;
		}
		if (ud_disassemble(&run_ud) == 0) {
			ret = NO_MATCH;
			goto out;
		}

		if (mode == RUN_PRE_DEBUG) {
			ksdebug(pack, "| ");
			print_bytes(pack, run, ud_insn_len(&run_ud),
				    pre, ud_insn_len(&pre_ud));
		}

		if (run_ud.mnemonic != pre_ud.mnemonic) {
			if (mode == RUN_PRE_DEBUG)
				ksdebug(pack, "mnemonic mismatch: %s %s\n",
					ud_lookup_mnemonic(run_ud.mnemonic),
					ud_lookup_mnemonic(pre_ud.mnemonic));
			ret = NO_MATCH;
			goto out;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20) && \
    defined(_I386_BUG_H) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11) || \
			     defined(CONFIG_DEBUG_BUGVERBOSE))
/* 91768d6c2bad0d2766a166f13f2f57e197de3458 was after 2.6.19 */
/* 38326f786cf4529a86b1ccde3aa17f4fa7e8472a was after 2.6.10 */
		if (run_ud.mnemonic == UD_Iud2) {
			/* ud2 means BUG().  On old i386 kernels, it is followed
			   by 2 bytes and then a 4-byte relocation; and is not
			   disassembler-friendly. */
			const struct ksplice_reloc *r;
			ret = lookup_reloc(pack, (unsigned long)(pre + 4), &r);
			if (ret == NO_MATCH) {
				if (mode == RUN_PRE_INITIAL)
					ksdebug(pack, "Unrecognized ud2\n");
				goto out;
			}
			if (ret != OK)
				goto out;
			ret = handle_reloc(pack, r, (unsigned long)(run + 4),
					   mode);
			if (ret != OK)
				goto out;
			/* If there's a relocation, then it's a BUG? */
			if (mode == RUN_PRE_DEBUG) {
				ksdebug(pack, "[BUG?: ");
				print_bytes(pack, run + 2, 6, pre + 2, 6);
				ksdebug(pack, "] ");
			}
			pre += 8;
			run += 8;
			ud_input_skip(&run_ud, 6);
			ud_input_skip(&pre_ud, 6);
			continue;
		}
#endif /* LINUX_VERSION_CODE && _I386_BUG_H && CONFIG_DEBUG_BUGVERBOSE */

		for (i = 0; i < ARRAY_SIZE(run_ud.operand); i++) {
			ret = compare_operands(pack, s, match_map, run_addr,
					       run, pre, &run_ud, &pre_ud, i,
					       mode);
			if (ret != OK)
				goto out;
		}
		run += ud_insn_len(&run_ud);
		pre += ud_insn_len(&pre_ud);

		/* Nops are the only sense in which the instruction
		   sequences are allowed to not match */
		runc = match_nop(run);
		prec = match_nop(pre);
		if (runc > 0 || prec > 0) {
			if (mode == RUN_PRE_DEBUG)
				print_bytes(pack, run, runc, pre, prec);
			ud_input_skip(&run_ud, runc);
			ud_input_skip(&pre_ud, prec);
			run += runc;
			pre += prec;
		}

		if ((unsigned long)pre - pre_addr >= s->size)
			continue;

		if (match_map[(unsigned long)pre - pre_addr] ==
		    (unsigned long)run)
			continue;

		if (match_map[(unsigned long)pre - pre_addr] == 0) {
			match_map[(unsigned long)pre - pre_addr] =
			    (unsigned long)run;
			continue;
		}

		/* This condition should occur for jumps into an ELF subsection.
		   Check that the last instruction was an unconditional change
		   of control */
		if (!(run_ud.mnemonic == UD_Ijmp ||
		      run_ud.mnemonic == UD_Iret ||
		      run_ud.mnemonic == UD_Iretf ||
		      run_ud.mnemonic == UD_Iiretw ||
		      run_ud.mnemonic == UD_Iiretd ||
		      run_ud.mnemonic == UD_Iiretq ||
		      run_ud.mnemonic == UD_Isysexit ||
		      run_ud.mnemonic == UD_Isysret ||
		      run_ud.mnemonic == UD_Isyscall ||
		      run_ud.mnemonic == UD_Isysenter)) {
			ksdebug(pack, "<--[No unconditional change of "
				"control at control transfer point %lx]\n",
				(unsigned long)pre - pre_addr);
			return NO_MATCH;
		}

		if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, " [Moving run pointer for %lx from %lx "
				"to %lx]\n", (unsigned long)pre - pre_addr,
				(unsigned long)run - run_addr,
				match_map[(unsigned long)pre - pre_addr]
				- run_addr);

		/* Create a safety_record for the block just matched */
		ret = create_safety_record(pack, s, safety_records,
					   run_start,
					   (unsigned long)run - run_start);
		if (ret != OK)
			goto out;

		/* We re-initialize the ud structure because
		   it may have cached upcoming bytes */
		run = (const unsigned char *)
		    match_map[(unsigned long)pre - pre_addr];
		ud_init(&run_ud);
		ud_set_mode(&run_ud, BITS_PER_LONG);
		ud_set_syntax(&run_ud, UD_SYN_ATT);
		ud_set_input_hook(&run_ud, next_run_byte);
		ud_set_pc(&run_ud, 0);
		run_ud.userdata = (unsigned char *)run;
		run_start = (unsigned long)run;
	}
out:
	vfree(match_map);
	return ret;
}

static abort_t compare_operands(struct ksplice_pack *pack,
				const struct ksplice_size *s,
				unsigned long *match_map,
				unsigned long run_addr,
				const unsigned char *run,
				const unsigned char *pre, struct ud *run_ud,
				struct ud *pre_ud, int opnum,
				enum run_pre_mode mode)
{
	abort_t ret;
	int i;
	unsigned long pre_addr = s->thismod_addr;
	struct ud_operand *run_op = &run_ud->operand[opnum];
	struct ud_operand *pre_op = &pre_ud->operand[opnum];
	uint8_t run_off = ud_prefix_len(run_ud);
	uint8_t pre_off = ud_prefix_len(pre_ud);
	const struct ksplice_reloc *r;
	for (i = 0; i < opnum; i++) {
		run_off += ud_operand_len(&run_ud->operand[i]);
		pre_off += ud_operand_len(&pre_ud->operand[i]);
	}

	if (run_op->type != pre_op->type) {
		if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, "type mismatch: %d %d\n", run_op->type,
				pre_op->type);
		return NO_MATCH;
	}
	if (run_op->base != pre_op->base) {
		if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, "base mismatch: %d %d\n", run_op->base,
				pre_op->base);
		return NO_MATCH;
	}
	if (run_op->index != pre_op->index) {
		if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, "index mismatch: %d %d\n",
				run_op->index, pre_op->index);
		return NO_MATCH;
	}
	if (ud_operand_len(run_op) == 0 && ud_operand_len(pre_op) == 0)
		return OK;

	ret = lookup_reloc(pack, (unsigned long)(pre + pre_off), &r);
	if (ret == OK) {
		struct ksplice_reloc run_reloc = *r;
		if (r->size != ud_operand_len(pre_op)) {
			ksdebug(pack, "ksplice_h: run-pre: reloc size %d "
				"differs from disassembled size %d\n", r->size,
				ud_operand_len(pre_op));
			return NO_MATCH;
		}
		if (r->size != ud_operand_len(run_op) &&
		    (r->dst_mask != 0xffffffff || r->rightshift != 0)) {
			/* Special features unsupported with differing reloc sizes */
			ksdebug(pack, "ksplice_h: reloc: invalid flags for a "
				"relocation with size changed\n");
			ksdebug(pack, "%ld %u\n", r->dst_mask, r->rightshift);
			return UNEXPECTED;
		}
		/* adjust for differing relocation size */
		run_reloc.size = ud_operand_len(run_op);
		if (r->size != run_reloc.size)
			run_reloc.dst_mask = ~(~0 << run_reloc.size * 8);
		run_reloc.addend += (ud_operand_len(pre_op) -
				     ud_operand_len(run_op));
		ret = handle_reloc(pack, &run_reloc,
				   (unsigned long)(run + run_off), mode);
		if (ret != OK) {
			if (mode == RUN_PRE_DEBUG)
				ksdebug(pack, "Matching failure at offset "
					"%lx\n", (unsigned long)pre - pre_addr);
			return ret;
		}
		/* This operand is a successfully processed relocation */
		return OK;
	} else if (ret != NO_MATCH) {
		return ret;
	}
	if (pre_op->type == UD_OP_JIMM) {
		/* Immediate jump without a relocation */
		unsigned long pre_target = (unsigned long)pre +
		    ud_insn_len(pre_ud) + jump_lval(pre_op);
		unsigned long run_target = (unsigned long)run +
		    ud_insn_len(run_ud) + jump_lval(run_op);
		if (pre_target == run_target) {
			/* Paravirt-inserted pcrel jump; OK! */
			return OK;
		} else if (pre_target >= pre_addr &&
			   pre_target < pre_addr + s->size) {
			/* Jump within the current function.
			   Check it's to a corresponding place */
			if (mode == RUN_PRE_DEBUG)
				ksdebug(pack, "[Jumps: pre=%lx run=%lx "
					"pret=%lx runt=%lx] ",
					(unsigned long)pre - pre_addr,
					(unsigned long)run - run_addr,
					pre_target - pre_addr,
					run_target - run_addr);
			if (match_map[pre_target - pre_addr] != 0 &&
			    match_map[pre_target - pre_addr] != run_target) {
				ksdebug(pack, "<--[Jumps to nonmatching "
					"locations]\n");
				return NO_MATCH;
			} else if (match_map[pre_target - pre_addr] == 0) {
				match_map[pre_target - pre_addr] = run_target;
			}
			return OK;
		} else {
			if (mode == RUN_PRE_DEBUG) {
				ksdebug(pack, "<--Different operands!\n");
				ksdebug(pack, "%lx %lx %lx %lx %x %lx %lx "
					"%lx\n", pre_addr, pre_target,
					pre_addr + s->size, (unsigned long)pre,
					ud_insn_len(pre_ud), s->size,
					jump_lval(pre_op), run_target);
			}
			return NO_MATCH;
		}
	} else if (ud_operand_len(pre_op) == ud_operand_len(run_op) &&
		   memcmp(pre + pre_off, run + run_off,
			  ud_operand_len(run_op)) == 0) {
		return OK;
	} else {
		if (mode == RUN_PRE_DEBUG)
			ksdebug(pack, "<--Different operands!\n");
		return NO_MATCH;
	}
}

static int match_nop(const unsigned char *addr)
{
	int i, j;
	const struct insn *nop;
	for (i = NUM_NOPS - 1; i >= 0; i--) {
		nop = &nops[i];
		for (j = 0; j < nop->len; j++) {
			unsigned char byte;
			if (probe_kernel_read(&byte, (void *)&addr[j], 1) ==
			    -EFAULT)
				break;
			if (byte != nop->data[j])
				break;
		}
		if (j == nop->len)
			return j;
	}
	return 0;
}

static uint8_t ud_operand_len(struct ud_operand *operand)
{
	if (operand->type == UD_OP_MEM)
		return operand->offset / 8;
	if (operand->type == UD_OP_REG)
		return 0;
	return operand->size / 8;
}

static uint8_t ud_prefix_len(struct ud *ud)
{
	int len = ud_insn_len(ud);
	int i;
	for (i = 0; i < ARRAY_SIZE(ud->operand); i++)
		len -= ud_operand_len(&ud->operand[i]);
	return len;
}

static long jump_lval(struct ud_operand *operand)
{
	if (operand->type == UD_OP_JIMM) {
		switch(operand->size) {
		case 8:
			return operand->lval.sbyte;
		case 16:
			return operand->lval.sword;
		case 32:
			return operand->lval.sdword;
		case 64:
			return operand->lval.sqword;
		default:
			return 0;
		}
	}
	return 0;
}

static int next_run_byte(struct ud *ud)
{
	unsigned char byte;
	if (probe_kernel_read(&byte, ud->userdata, 1) == -EFAULT)
		return UD_EOI;
	ud->userdata++;
	return byte;
}
#endif /* !CONFIG_FUNCTION_DATA_SECTIONS */

static unsigned long trampoline_target(unsigned long addr)
{
	unsigned char bytes[5];

	if (probe_kernel_read(bytes, (void *)addr, sizeof(bytes)) == -EFAULT)
		return addr;

	if (bytes[0] == 0xE9)
		return addr + 5 + *(int32_t *)(&bytes[1]);
	return addr;
}

static abort_t create_trampoline(struct ksplice_patch *p)
{
	p->trampoline[0] = 0xE9;
	*(u32 *)(&p->trampoline[1]) = p->repladdr - (p->oldaddr + 5);
	p->size = 5;
	return OK;
}

static abort_t handle_paravirt(struct ksplice_pack *pack,
			       unsigned long pre_addr, unsigned long run_addr,
			       int *matched)
{
	unsigned char run[5], pre[5];
	*matched = 0;

	if (probe_kernel_read(&run, (void *)run_addr, sizeof(run)) == -EFAULT ||
	    probe_kernel_read(&pre, (void *)pre_addr, sizeof(pre)) == -EFAULT)
		return OK;

	if ((run[0] == 0xe8 && pre[0] == 0xe8) ||
	    (run[0] == 0xe9 && pre[0] == 0xe9))
		if (run_addr + 1 + *(int32_t *)&run[1] ==
		    pre_addr + 1 + *(int32_t *)&pre[1])
			*matched = 5;
	return OK;
}

static bool valid_stack_ptr(const struct thread_info *tinfo, const void *p)
{
	return p > (const void *)tinfo
	    && p <= (const void *)tinfo + THREAD_SIZE - sizeof(long);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static bool virtual_address_mapped(unsigned long addr)
{
	pgd_t *pgd;
#ifdef pud_page
	pud_t *pud;
#endif /* pud_page */
	pmd_t *pmd;
	pte_t *pte;

#ifdef KSPLICE_STANDALONE
	if (!bootstrapped)
		return true;
#endif /* KSPLICE_STANDALONE */

	pgd = pgd_offset_k(addr);
	if (!pgd_present(*pgd))
		return false;

#ifdef pud_page
	pud = pud_offset(pgd, addr);
	if (!pud_present(*pud))
		return false;

	pmd = pmd_offset(pud, addr);
#else /* pud_page */
	pmd = pmd_offset(pgd, addr);
#endif /* pud_page */

	if (!pmd_present(*pmd))
		return false;

	if (pmd_large(*pmd))
		return true;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte_present(*pte))
		return false;

	return true;
}
#endif /* LINUX_VERSION_CODE */
