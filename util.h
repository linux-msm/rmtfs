#ifndef __UTIL_H__
#define __UTIL_H__

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

void print_hex_dump(const char *prefix, const void *buf, size_t len);

#endif
