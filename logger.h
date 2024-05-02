
#pragma once

#include "lib.h"

  void
logger_init(const int fd);

__attribute__ ((format (printf, 1, 2)))
  void
logger_printf(const char * const fmt, ...);

