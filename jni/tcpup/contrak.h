#ifndef _TCP_CONTRAK_
#define _TCP_CONTRAK_

typedef int tcpup_out_f(int, const void *, size_t, int);

int tcp_reset_fill(unsigned char *buf, unsigned char *packet, size_t length);
int tcpup_reset_fill(unsigned char *buf, unsigned char *packet, size_t length);

int translate_up2ip(unsigned char *buf, size_t size, unsigned char *packet, size_t length);
int translate_ip2up(unsigned char *buf, size_t size, unsigned char *packet, size_t length, int *pxdat);

int tcpup_do_keepalive(tcpup_out_f *output, int tunnel, int xdat);

#endif

