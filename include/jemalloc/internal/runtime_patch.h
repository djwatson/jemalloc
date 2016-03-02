#ifdef JEMALLOC_H_TYPES

#if	defined(JEMALLOC_RUNTIME_PATCHING) && \
	defined(__x86_64__) && \
	defined(__OPTIMIZE__) && \
	(__GNUC__ > 4 || (__GNUC_MINOR__ >= 5 && __GNUC__ == 4))
#  define X86_64_PATCHING
#endif

typedef struct jmp_desc_s jmp_desc_t;

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

struct jmp_desc_s {
	bool *option;
	void *jump_from;
	void *jump_to;
} __attribute__((packed));

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

#ifdef X86_64_PATCHING
void malloc_patch_option(bool* option);
#endif

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifdef X86_64_PATCHING

/* Must *always* be inlined */
JEMALLOC_ALWAYS_INLINE_C bool
malloc_option_default_off(bool* option) {
	asm goto (
		/* 8-byte noop, enough space for a 32-bit jmp later */
		"0: .byte 0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;"
		/* Save address of option in jmp_table for later patching */
		".pushsection jmp_table, \"a\";"
		".quad %c0, 0b, %l1;"
		".popsection"
	: : "i" (option) : : foo);
	return false;
	if (0) {
		foo:
			return true;
	}
}

JEMALLOC_ALWAYS_INLINE_C bool
malloc_option_default_on(bool* option) {
	asm goto (
		/* 32bit jmp */
		"0: .byte 0xe9 \n\t"
		/* relative jmp address */
		".long %l1 - 0b - 5\n\t"
		/* Unused, we always jmp over these bytes,
		 * but they're needed for aligned writes */
		".byte 0x00\n\t"
		".byte 0x00\n\t"
		".byte 0x00\n\t"
		/* Save address of option in jmp_table for later patching */
		".pushsection jmp_table, \"a\";"
		".quad %c0, 0b, %l1;"
		".popsection"
      : : "i" (option) : : foo);
	return false;
	if (0) {
		foo:
			return true;
	}
}

#else /* X86_64_PATCHING */

/* Always inline these, even in debug mode, for clarity */
JEMALLOC_ALWAYS_INLINE_C void __attribute__((unused))
malloc_patch_option(bool* option) {}
JEMALLOC_ALWAYS_INLINE_C bool __attribute__((unused))
malloc_option_default_off(bool* option) {
	return *option;
}
JEMALLOC_ALWAYS_INLINE_C bool __attribute__((unused))
malloc_option_default_on(bool* option) {
	return *option;
}

#endif /* X86_64_PATCHING */

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
