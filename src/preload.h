#ifndef PRELOAD_H
#define PRELOAD_H

// preload_main is called via static initializer when dynamic loader loads
// axon as a shared object
void preload_main(int argc, char **argv, char **env);

#endif
