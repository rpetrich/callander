#ifndef TIME_H
#define TIME_H

#include "loader.h"
#include <time.h>

// clock_gettime gets the current time in the clock specified
extern int clock_gettime(clockid_t clk_id, struct timespec *tp);

// clock_load loads the clock source from the AT_SYSINFO_EHDR auxiliary vector
extern void clock_load(ElfW(auxv_t) *auxv);

#endif
