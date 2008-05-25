#include <linux/pagemap.h>
#include <linux/sched.h>

int init_module(void);
void cleanup_module(void);
int ksplice_do_helper(void);
void *ksplice_kcalloc(int size);
int search_for_match(struct ksplice_size *s, int *stage);
int try_addr(struct ksplice_size *s, long run_addr, long pre_addr,
	     int create_nameval);
int run_pre_cmp(long run_addr, long pre_addr, int size, int rerun);
int handle_myst_reloc(long pre_addr, int *pre_z, long run_addr,
		      int *run_z, struct reloc_addrmap *map, int rerun);
int match_nop(long addr, int *main_o, int *other_o);
void brute_search_all_mods(struct ksplice_size *s);

static inline int
virtual_address_mapped(long addr)
{
	pgd_t *pgd;
#if defined(pud_page)
	pud_t *pud;
#endif
	pmd_t *pmd;
	pte_t *ptep;

	if (addr > init_mm.start_code && addr < init_mm.end_code)
		return 1;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return 0;

#if defined(pud_page)
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
#else
	pmd = pmd_offset(pgd, addr);
#endif

	if (pmd_none(*pmd))
		return 0;
	ptep = pte_offset_map(pmd, addr);
	if (!pte_present(*ptep)) {
		pte_unmap(ptep);
		return 0;
	}
	pte_unmap(ptep);

	return 1;
}

static inline int
brute_search(struct ksplice_size *s, void *start, long len)
{
	long addr;
	char run, pre;

	for (addr = (long) start; addr < (long) start + len; addr++) {
		if (addr % 100000 == 0)
			yield();

		if (!virtual_address_mapped(addr))
			return 1;

		run = *(unsigned char *) (addr);
		pre = *(unsigned char *) (s->thismod_addr);

		if (run != pre)
			return 1;

		if (addr == s->thismod_addr)
			return 1;

		if (try_addr(s, addr, s->thismod_addr, 1))
			return 0;
	}

	return 1;
}
