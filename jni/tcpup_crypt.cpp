#include <stdio.h>
#include <string.h>
#include "tcpup/crypt.h"

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

#ifdef DISABLE_ENCRYPT
	memmove(dst, src, len);
	return len;
#endif

	for (int i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}

int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len)
{
	unsigned int d0 = key;
	unsigned char *fdst = (unsigned char *)dst;
	const unsigned char *fsrc = (const unsigned char *)src;

#ifdef DISABLE_ENCRYPT
	memmove(dst, src, len);
	return len;
#endif

	for (int i = 0; i < len; i++) {
		*fdst++ = (*fsrc++ ^ d0);
		d0 = (d0 * 123 + 59) & 0xffff;
	}

	return 0;
}
