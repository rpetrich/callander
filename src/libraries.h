#ifndef LIBRARIES_H
#define LIBRARIES_H

#include "loader.h"

#include <link.h>

// update_libraries indexes the state of userland libraries
void update_libraries(struct link_map *map);

#endif
