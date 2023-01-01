#ifndef SECCOMP_H
#define SECCOMP_H

// apply_seccomp applies the standard seccomp filter that traps on exec and any enabled_telemetry
__attribute__((warn_unused_result))
extern int apply_seccomp(void);
extern const char *const empty_string;

#endif
