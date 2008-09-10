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

#include <linux/kernel.h>
#include <asm/thread_info.h>
#define KSPLICE_IP(x) thread_saved_pc(x)
#define KSPLICE_SP(x) thread_saved_fp(x)

static unsigned long trampoline_target(unsigned long addr)
{
	uint32_t word;
	unsigned long new_addr;

	if (probe_kernel_read(&word, (void *)addr, sizeof(word)) == -EFAULT)
		return addr;

	if ((word & 0xff000000) == 0xea000000) {
		new_addr = word & 0x00ffffff;
		new_addr |= -(new_addr & (0x00ffffff & ~(0x00ffffff >> 1)));
		new_addr <<= 2;
		new_addr += addr + 8;
		return new_addr;
	}
	return addr;
}

static abort_t create_trampoline(struct ksplice_patch *p)
{
	int32_t tmp = p->repladdr - (p->oldaddr + 8);
	tmp >>= 2;
	tmp &= 0x00ffffff;
	*(uint32_t *)p->trampoline = 0xea000000 | tmp;
	p->size = 4;
	return OK;
}

static abort_t handle_paravirt(struct module_pack *pack, unsigned long pre_addr,
			       unsigned long run_addr, int *matched)
{
	*matched = 0;
	return OK;
}
