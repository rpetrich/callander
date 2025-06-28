#ifndef LIBCALLANDER_H
#define LIBCALLANDER_H

#if __STDC_VERSION__ >= 201112L
#include <stdnoreturn.h>
#endif

typedef int (*callander_main_function)(void *data);

#if __STDC_VERSION__ >= 201112L
noreturn
#endif
	void
	callander_run(callander_main_function main, void *data);

#endif
