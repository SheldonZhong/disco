#define _GNU_SOURCE

#include "logger.h"
#include <stdarg.h> // va_start

static int logger_fd = 1;

  void
logger_init(const int fd)
{
  logger_fd = fd;
}

__attribute__ ((format (printf, 1, 2)))
  void
logger_printf(const char * const fmt, ...)
{
  char buf[64] = {};
  time_stamp2(buf, 64);

  dprintf(logger_fd, "%s %08x ", buf, crc32c_u64(0x12345678, (u64)pthread_self()));

  va_list ap;
  va_start(ap, fmt);
  vdprintf(logger_fd, fmt, ap);
  va_end(ap);
}

