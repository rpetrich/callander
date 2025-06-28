#ifndef QSORT_H
#define QSORT_H

#include <stdbool.h>

void qsort_r_freestanding(void *base, size_t nel, size_t width, int (*compar)(const void *, const void *, void *), void *arg);
#if 0
void *bsearch(const void *key, const void *base, size_t nel, size_t width, int (*cmp)(const void *, const void *));
#else
__attribute__((always_inline)) static inline void *bsearch_inline(const void *key, const void *base, size_t nel, size_t width, int (*cmp)(const void *, const void *))
{
	void *try;
	int sign;
	while (nel > 0) {
		try = (char *)base + width * (nel / 2);
		sign = cmp(key, try);
		if (!sign)
			return try;
		else if (nel == 1)
			break;
		else if (sign < 0)
			nel /= 2;
		else {
			base = try;
			nel -= nel / 2;
		}
	}
	return NULL;
}
#endif

static inline int bsearch_bool(int n, void *data, void *more_data, bool (*f)(int, void *data, void *more_data))
{
	int i = 0;
	int j = n;
	while (i < j) {
		int h = (int)((unsigned int)(i + j) >> 1); // avoid overflow when computing h
		// i ≤ h < j
		if (!f(h, data, more_data)) {
			i = h + 1; // preserves f(i-1) == false
		} else {
			j = h; // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i;
}

#endif
