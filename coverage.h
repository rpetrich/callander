#ifndef COVERAGE_H
#define COVERAGE_H

struct coverage_data {
#ifdef COVERAGE
	int err;
#endif
};


// coverage_flush will write the current coverage state to disk
void coverage_flush(void);

#endif
