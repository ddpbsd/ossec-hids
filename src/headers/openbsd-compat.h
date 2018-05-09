#include <sys/types.h>

#ifndef HAVE_STRLCAT
size_t strlcpy(char *dst, const char *src, size_t size);

size_t strlcat(char *dst, const char *src, size_t size);
#endif	// HAVE_STRLCAT
