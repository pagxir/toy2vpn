#ifndef _TCP_CRYPT_H_
#define _TCP_CRYPT_H_

int packet_decrypt(unsigned short key, void *dst, const void *src, size_t len);
int packet_encrypt(unsigned short key, void *dst, const void *src, size_t len);

#endif
