static const char jumplen[256] = {[0x0f] = 5,	/* je */
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
