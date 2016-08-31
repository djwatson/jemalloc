#include <pthread.h>
#include "rseq.h"

/******************************************************************************/
#ifdef JEMALLOC_H_TYPES

typedef struct tcache_bin_info_s tcache_bin_info_t;
typedef struct tcache_bin_s tcache_bin_t;
typedef struct tcache_s tcache_t;
typedef struct tcaches_s tcaches_t;

/*
 * tcache pointers close to NULL are used to encode state information that is
 * used for two purposes: preventing thread caching on a per thread basis and
 * cleaning up during thread shutdown.
 */
#define	TCACHE_STATE_DISABLED		((tcache_t *)(uintptr_t)1)
#define	TCACHE_STATE_REINCARNATED	((tcache_t *)(uintptr_t)2)
#define	TCACHE_STATE_PURGATORY		((tcache_t *)(uintptr_t)3)
#define	TCACHE_STATE_MAX		TCACHE_STATE_PURGATORY

/*
 * Absolute minimum number of cache slots for each small bin.
 */
#define	TCACHE_NSLOTS_SMALL_MIN		20

/*
 * Absolute maximum number of cache slots for each small bin in the thread
 * cache.  This is an additional constraint beyond that imposed as: twice the
 * number of regions per run for this size class.
 *
 * This constant must be an even number.
 */
#define	TCACHE_NSLOTS_SMALL_MAX		200

/* Number of cache slots for large size classes. */
#define	TCACHE_NSLOTS_LARGE		20

/* (1U << opt_lg_tcache_max) is used to compute tcache_maxclass. */
#define	LG_TCACHE_MAXCLASS_DEFAULT	15

/*
 * TCACHE_GC_SWEEP is the approximate number of allocation events between
 * full GC sweeps.  Integer rounding may cause the actual number to be
 * slightly higher, since GC is performed incrementally.
 */
#define	TCACHE_GC_SWEEP			8192

/* Number of tcache allocation/deallocation events between incremental GCs. */
#define	TCACHE_GC_INCR							\
    ((TCACHE_GC_SWEEP / NBINS) + ((TCACHE_GC_SWEEP / NBINS == 0) ? 0 : 1))

#endif /* JEMALLOC_H_TYPES */
/******************************************************************************/
#ifdef JEMALLOC_H_STRUCTS

typedef enum {
	tcache_enabled_false   = 0, /* Enable cast to/from bool. */
	tcache_enabled_true    = 1,
	tcache_enabled_default = 2
} tcache_enabled_t;

/*
 * Read-only information associated with each element of tcache_t's tbins array
 * is stored separately, mainly to reduce memory usage.
 */
struct tcache_bin_info_s {
	unsigned	ncached_max;	/* Upper limit on ncached. */
};

struct tcache_bin_s {
	tcache_bin_stats_t tstats;
	long		low_water;	/* Min # cached since last GC. */
	unsigned	lg_fill_div;	/* Fill (ncached_max >> lg_fill_div). */
	unsigned long	ncached;	/* # of cached objects. */
	/*
	 * To make use of adjacent cacheline prefetch, the items in the avail
	 * stack goes to higher address for newer allocations.  avail points
	 * just above the available space, which means that
	 * avail[-ncached, ... -1] are available items and the lowest item will
	 * be allocated first.
	 */
	void		**avail;	/* Stack of available objects. */
};

struct tcache_s {
	ql_elm(tcache_t) link;		/* Used for aggregating stats. */
	uint64_t	prof_accumbytes;/* Cleared after arena_prof_accum(). */
	ticker_t	gc_ticker;	/* Drives incremental GC. */
	szind_t		next_gc_bin;	/* Next bin to GC. */
	tcache_bin_t	tbins[1];	/* Dynamically sized. */
	/*
	 * The pointer stacks associated with tbins follow as a contiguous
	 * array.  During tcache initialization, the avail pointer in each
	 * element of tbins is initialized to point to the proper offset within
	 * this array.
	 */
};

/* Linkage for list of available (previously used) explicit tcache IDs. */
struct tcaches_s {
	union {
		tcache_t	*tcache;
		tcaches_t	*next;
	};
};

#endif /* JEMALLOC_H_STRUCTS */
/******************************************************************************/
#ifdef JEMALLOC_H_EXTERNS

extern bool	opt_tcache;
extern ssize_t	opt_lg_tcache_max;

extern tcache_bin_info_t	*tcache_bin_info;

/*
 * Number of tcache bins.  There are NBINS small-object bins, plus 0 or more
 * large-object bins.
 */
extern unsigned	nhbins;

/* Maximum cached size class. */
extern size_t	tcache_maxclass;

/*
 * Explicit tcaches, managed via the tcache.{create,flush,destroy} mallctls and
 * usable via the MALLOCX_TCACHE() flag.  The automatic per thread tcaches are
 * completely disjoint from this data structure.  tcaches starts off as a sparse
 * array, so it has no physical memory footprint until individual pages are
 * touched.  This allows the entire array to be allocated the first time an
 * explicit tcache is created without a disproportionate impact on memory usage.
 */
extern tcaches_t	*tcaches;

extern struct rseq_lock rseq_lock;


size_t	tcache_salloc(tsdn_t *tsdn, const void *ptr);
void	tcache_event_hard(int cpu, tsd_t *tsd, tcache_t *tcache);
void	*tcache_alloc_small_hard(int cpu, tsdn_t *tsdn, arena_t *arena, tcache_t *tcache,
    tcache_bin_t *tbin, szind_t binind, bool *tcache_success);
void	tcache_bin_flush_small(tsd_t *tsd, tcache_t *tcache, void** ptrs,
    szind_t binind, unsigned rem);
void	tcache_bin_flush_large(tsd_t *tsd, void**ptrs, szind_t binind,
    unsigned rem, tcache_t *tcache);
void	tcache_arena_reassociate(tsdn_t *tsdn, tcache_t *tcache,
    arena_t *oldarena, arena_t *newarena);
tcache_t *tcache_get_hard(tsd_t *tsd);
tcache_t *tcache_create(tsdn_t *tsdn, arena_t *arena);
void	tcache_cleanup(tsd_t *tsd);
void	tcache_enabled_cleanup(tsd_t *tsd);
void	tcache_stats_merge(tsdn_t *tsdn, tcache_t *tcache, arena_t *arena);
bool	tcaches_create(tsdn_t *tsdn, unsigned *r_ind);
void	tcaches_flush(tsd_t *tsd, unsigned ind);
void	tcaches_destroy(tsd_t *tsd, unsigned ind);
bool	tcache_boot(tsdn_t *tsdn);

#endif /* JEMALLOC_H_EXTERNS */
/******************************************************************************/
#ifdef JEMALLOC_H_INLINES

#ifndef JEMALLOC_ENABLE_INLINE
void	tcache_event(int cpu, tsd_t *tsd, tcache_t *tcache);
void	tcache_flush(void);
bool	tcache_enabled_get(void);
tcache_t *tcache_get(tsd_t *tsd, bool create);
void	tcache_enabled_set(bool enabled);
void	*tcache_alloc_easy(struct rseq_state* start, tcache_bin_t *tbin, bool *tcache_success);
void	*tcache_alloc_small(tsd_t *tsd, arena_t *arena, tcache_t *tcache,
    size_t size, szind_t ind, bool zero, bool slow_path);
void	*tcache_alloc_large(tsd_t *tsd, arena_t *arena, tcache_t *tcache,
    size_t size, szind_t ind, bool zero, bool slow_path);
void	tcache_dalloc_small(tsd_t *tsd, tcache_t *tcache, void *ptr,
    szind_t binind, bool slow_path);
void	tcache_dalloc_large(tsd_t *tsd, tcache_t *tcache, void *ptr,
    size_t size, bool slow_path);
tcache_t	*tcaches_get(tsd_t *tsd, unsigned ind);
#endif

#if (defined(JEMALLOC_ENABLE_INLINE) || defined(JEMALLOC_TCACHE_C_))
JEMALLOC_INLINE void
tcache_flush(void)
{
	tsd_t *tsd;

	cassert(config_tcache);

	tsd = tsd_fetch();
	tcache_cleanup(tsd);
}

JEMALLOC_INLINE bool
tcache_enabled_get(void)
{
	tsd_t *tsd;
	tcache_enabled_t tcache_enabled;

	cassert(config_tcache);

	tsd = tsd_fetch();
	tcache_enabled = tsd_tcache_enabled_get(tsd);
	if (tcache_enabled == tcache_enabled_default) {
		tcache_enabled = (tcache_enabled_t)opt_tcache;
		tsd_tcache_enabled_set(tsd, tcache_enabled);
	}

	return ((bool)tcache_enabled);
}

JEMALLOC_INLINE void
tcache_enabled_set(bool enabled)
{
	tsd_t *tsd;
	tcache_enabled_t tcache_enabled;

	cassert(config_tcache);

	tsd = tsd_fetch();

	tcache_enabled = (tcache_enabled_t)enabled;
	tsd_tcache_enabled_set(tsd, tcache_enabled);

	if (!enabled)
		tcache_cleanup(tsd);
}

JEMALLOC_ALWAYS_INLINE tcache_t *
tcache_get(tsd_t *tsd, bool create)
{
	tcache_t *tcache;

	if (!config_tcache)
		return (NULL);

	tcache = tsd_tcache_get(tsd);
	if (!create)
		return (tcache);
	if (unlikely(tcache == NULL) && tsd_nominal(tsd)) {
		tcache = tcache_get_hard(tsd);
		tsd_tcache_set(tsd, tcache);
	}

	return (tcache);
}

JEMALLOC_ALWAYS_INLINE void
tcache_event(int cpu, tsd_t *tsd, tcache_t *tcache)
{

	if (TCACHE_GC_INCR == 0)
		return;

	if (unlikely(ticker_tick(&tcache->gc_ticker)))
	  tcache_event_hard(cpu, tsd, tcache);
}

JEMALLOC_ALWAYS_INLINE void *
tcache_alloc_easy(struct rseq_state* start, tcache_bin_t *tbin, bool *tcache_success)
{
	void *ret;

  *tcache_success = false;
  if (unlikely(tbin->ncached == 0)) {
	return (NULL);
  }

  ret = *(tbin->avail - tbin->ncached);

  assert(ret != NULL);

  if (rseq_finish(&rseq_lock, (intptr_t*)&tbin->ncached, (intptr_t)tbin->ncached-1, *start)) {
    *tcache_success = true;
    return ret;
  }

  return NULL;

}

JEMALLOC_ALWAYS_INLINE void *
tcache_alloc_small(tsd_t *tsd, arena_t *arena, tcache_t *tcache, size_t size,
    szind_t binind, bool zero, bool slow_path)
{
	void *ret = NULL;
	tcache_bin_t *tbin;
	bool tcache_success;
	size_t usize JEMALLOC_CC_SILENCE_INIT(0);
	int cpu;

	struct rseq_state start;

	start = rseq_start(&rseq_lock);
	cpu = rseq_cpu_at_start(start);
        tcache = tcaches[cpu].tcache;

        tbin = &tcache->tbins[binind];

        ret = tcache_alloc_easy(&start, tbin, &tcache_success);

        if (unlikely(!tcache_success)) {
          arena = arena_choose(tsd, arena);
          if (unlikely(arena == NULL))
            return (NULL);
          ret = tcache_alloc_small_hard(cpu, tsd_tsdn(tsd), arena, tcache, tbin, binind, &tcache_success);
        }

	assert(ret);
	/*
	 * Only compute usize if required.  The checks in the following if
	 * statement are all static.
	 */
	if (config_prof || (slow_path && config_fill) || unlikely(zero)) {
		usize = index2size(binind);
		assert(tcache_salloc(tsd_tsdn(tsd), ret) == usize);
	}

	if (likely(!zero)) {
		if (slow_path && config_fill) {
			if (unlikely(opt_junk_alloc)) {
				arena_alloc_junk_small(ret,
				    &arena_bin_info[binind], false);
			} else if (unlikely(opt_zero))
				memset(ret, 0, usize);
		}
	} else {
		if (slow_path && config_fill && unlikely(opt_junk_alloc)) {
			arena_alloc_junk_small(ret, &arena_bin_info[binind],
			    true);
		}
		memset(ret, 0, usize);
	}

	if (config_stats)
		tbin->tstats.nrequests++;
	if (config_prof)
		tcache->prof_accumbytes += usize;
	return (ret);
}

JEMALLOC_ALWAYS_INLINE void *
tcache_alloc_large(tsd_t *tsd, arena_t *arena, tcache_t *tcache, size_t size,
    szind_t binind, bool zero, bool slow_path)
{
	void *ret;
	tcache_bin_t *tbin;
	bool tcache_success;

        int cpu;
	struct rseq_state start;

  retry:
	start = rseq_start(&rseq_lock);
          cpu = rseq_cpu_at_start(start);
          tcache = tcaches[cpu].tcache;

	assert(binind < nhbins);
	tbin = &tcache->tbins[binind];
	ret = tcache_alloc_easy(&start, tbin, &tcache_success);
	assert(tcache_success == (ret != NULL));
	if (unlikely(!tcache_success)) {

          if (cpu != rseq_current_cpu())
            goto retry;
		/*
		 * Only allocate one large object at a time, because it's quite
		 * expensive to create one and not use it.
		 */
		arena = arena_choose(tsd, arena);
		if (unlikely(arena == NULL))
			return (NULL);

		ret = arena_malloc_large(tsd_tsdn(tsd), arena, binind, zero);
		if (ret == NULL)
			return (NULL);
	} else {
		size_t usize JEMALLOC_CC_SILENCE_INIT(0);

		/* Only compute usize on demand */
		if (config_prof || (slow_path && config_fill) ||
		    unlikely(zero)) {
			usize = index2size(binind);
			assert(usize <= tcache_maxclass);
		}

		if (config_prof && usize == LARGE_MINCLASS) {
			arena_chunk_t *chunk =
			    (arena_chunk_t *)CHUNK_ADDR2BASE(ret);
			size_t pageind = (((uintptr_t)ret - (uintptr_t)chunk) >>
			    LG_PAGE);
			arena_mapbits_large_binind_set(chunk, pageind,
			    BININD_INVALID);
		}
		if (likely(!zero)) {
			if (slow_path && config_fill) {
				if (unlikely(opt_junk_alloc)) {
					memset(ret, JEMALLOC_ALLOC_JUNK,
					    usize);
				} else if (unlikely(opt_zero))
					memset(ret, 0, usize);
			}
		} else
			memset(ret, 0, usize);

		if (config_stats)
			tbin->tstats.nrequests++;
		if (config_prof)
			tcache->prof_accumbytes += usize;
	}

	return (ret);
}

    void tcache_dalloc_small_memcpy(tsd_t *tsd, tcache_t *tcache, tcache_bin_t *tbin, szind_t binind,
				   struct rseq_state start);

JEMALLOC_ALWAYS_INLINE void
tcache_dalloc_small(tsd_t *tsd, tcache_t *tcache, void *ptr, szind_t binind,
    bool slow_path)
{
	tcache_bin_t *tbin;
	tcache_bin_info_t *tbin_info;
	int cpu;
	struct rseq_state start;
	unsigned long new;

  retry:
	start = rseq_start(&rseq_lock);
	cpu = rseq_cpu_at_start(start);
          tcache = tcaches[cpu].tcache;

          tbin = &tcache->tbins[binind];
          tbin_info = &tcache_bin_info[binind];

          new = tbin->ncached + 1;
          if (unlikely(tbin->ncached == tbin_info->ncached_max)) {
	    tcache_dalloc_small_memcpy(tsd, tcache, tbin, binind, start);

	    goto retry;
	  }

          if (!rseq_finish2(&rseq_lock,
                (intptr_t *)(tbin->avail - new), (intptr_t)ptr,
                (intptr_t*)&tbin->ncached, (intptr_t)new,
		start)) {
	    goto retry;
          }
}

void
tcache_dalloc_large_memcpy(tsd_t *tsd, tcache_t *tcache, tcache_bin_t *tbin, size_t size,
			  struct rseq_state start);

JEMALLOC_ALWAYS_INLINE void
tcache_dalloc_large(tsd_t *tsd, tcache_t *tcache, void *ptr, size_t size,
    bool slow_path)
{
	szind_t binind;
	tcache_bin_t *tbin;
	tcache_bin_info_t *tbin_info;
        int cpu;
	unsigned long old, new;
	struct rseq_state start;

	assert((size & PAGE_MASK) == 0);
	assert(tcache_salloc(tsd_tsdn(tsd), ptr) > SMALL_MAXCLASS);
	assert(tcache_salloc(tsd_tsdn(tsd), ptr) <= tcache_maxclass);

	binind = size2index(size);

	if (slow_path && config_fill && unlikely(opt_junk_free))
		arena_dalloc_junk_large(ptr, size);

  retry:
	  start = rseq_start(&rseq_lock);
          cpu = rseq_cpu_at_start(start);
          tcache = tcaches[cpu].tcache;

          tbin = &tcache->tbins[binind];

	  tbin_info = &tcache_bin_info[binind];

          old = tbin->ncached;
          new = old + 1;

          if (unlikely(tbin->ncached == tbin_info->ncached_max)) {
	    tcache_dalloc_large_memcpy(tsd, tcache, tbin, size, start);
	    goto retry;
          }
          assert(tbin->ncached < tbin_info->ncached_max);

          if (!rseq_finish2(&rseq_lock,
                (intptr_t *)(tbin->avail - new), (intptr_t)ptr,
                (intptr_t*)&tbin->ncached, (intptr_t)new,
		start)) {
	    goto retry;
          }
}

JEMALLOC_ALWAYS_INLINE tcache_t *
tcaches_get(tsd_t *tsd, unsigned ind)
{
	tcaches_t *elm = &tcaches[ind];
	if (unlikely(elm->tcache == NULL)) {
		elm->tcache = tcache_create(tsd_tsdn(tsd), arena_choose(tsd,
		    NULL));
	}
	return (elm->tcache);
}
#endif

#endif /* JEMALLOC_H_INLINES */
/******************************************************************************/
