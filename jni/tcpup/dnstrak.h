#ifndef _TCPUP_DNSTRAK_H_
#define _TCPUP_DNSTRAK_H_

int get_tunnel_udp(struct sockaddr_in *addrp);
int send_out_ip2udp(int lowfd, unsigned char *packet, size_t length);
int fill_out_ip2udp(char *buf, unsigned char *packet, size_t length);

int record_dns_packet(void *p, size_t l, struct sockaddr_in *f, struct sockaddr_in *d);
int resolved_dns_packet(void *b, const void *p, size_t l, struct sockaddr_in *f);

#endif
