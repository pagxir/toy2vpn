#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <time.h>
#include <errno.h>
#include <assert.h>

#include "tcpup/up.h"
#include "tcpup/ip.h"
#include "tcpup/dnstrak.h"

int get_tunnel_udp(struct sockaddr_in *addrp)
{
    int error;
	int mark = 0x01;

	int tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert(tunnel != -1);

#if 0
	error = setsockopt(tunnel, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    assert(error == 0);
#endif

	error = bind(tunnel, (struct sockaddr *)addrp, sizeof(*addrp));
    fprintf(stderr, "bind to %s\n", inet_ntoa(addrp->sin_addr));
    assert(error == 0);

	return tunnel;
}

struct dns_query_packet {
	unsigned short q_ident;
	unsigned short q_flags;
	unsigned short q_qdcount;
	unsigned short q_ancount;
	unsigned short q_nscount;
	unsigned short q_arcount;
};

static struct cached_client {
    int flags;
    unsigned short r_ident;
    unsigned short l_ident;

    union {
        struct sockaddr sa; 
        struct sockaddr_in in0;
    } from;
} __cached_client[512];

static int __last_index = 0;

int resolved_dns_packet(void *buf, const void *packet, size_t length, struct sockaddr_in *from)
{
	int flags;
	int index, ident;
	struct iphdr *ip;
	struct udphdr *udp;
	struct dns_query_packet *dnsp;
	struct dns_query_packet *dnsout;

	dnsp = (struct dns_query_packet *)packet;
	flags = ntohs(dnsp->q_flags);

	if (flags & 0x8000) {
		ip = (struct iphdr *)buf;
		udp = (struct udphdr *)(ip + 1);

		/* from dns server */;
		ident = htons(dnsp->q_ident);
		index = (ident & 0x1FF);

		struct cached_client *client = &__cached_client[index];
		if (client->flags == 1 &&
				client->r_ident == ident) {
			client->flags = 0;
			dnsp->q_ident = htons(client->l_ident);
			memcpy(udp + 1, packet, length);

			udp->len = htons(length + sizeof(*udp));
			udp->check = 0;
			udp->source = from->sin_port;
			udp->dest   = client->from.in0.sin_port;
			udp_checksum(&udp->check, &from->sin_addr,
					&client->from.in0.sin_addr, udp, length + sizeof(*udp));

			ip->ihl = 5;
			ip->version = 4;
			ip->tos = 0;
			ip->tot_len = htons(length + (char *)(udp + 1) - (char *)buf);
			ip->id  = (0xffff & (long)ip);
			ip->frag_off = htons(0x4000);
			ip->ttl = 8;
			ip->protocol = IPPROTO_UDP;
			ip->check = 0;

			ip->saddr = from->sin_addr.s_addr;
			ip->daddr = client->from.in0.sin_addr.s_addr;
			ip_checksum(&ip->check, ip, sizeof(*ip));

			return length + (char *)(udp + 1) - (char *)buf;
		}
	}

	return 0;
}

int record_dns_packet(void *packet, size_t length, struct sockaddr_in *from)
{
	int flags;
	struct dns_query_packet *dnsp;

	dnsp = (struct dns_query_packet *)packet;
	flags = ntohs(dnsp->q_flags);

	if (flags & 0x8000) {
#if 0
		/* from dns server */;
		int ident = htons(dnsp->q_ident);
		int index = (ident & 0x1FF);

		client = &__cached_client[index];
		if (client->flags == 1 &&
				client->r_ident == ident) {
			int error;
			char bufout[8192];

			client->flags = 0;
			if (!client->don2p) {
				dnsp->q_ident = htons(client->l_ident);
				err = sendto(up->sockfd, buf, count, 0, &client->from.sa, sizeof(client->from));
				fprintf(stderr, "sendto client %d/%d\n", err, errno);
				return 0;
			}
		}
#endif
		return 0;
	}

	/* from dns client */;
	int index = (__last_index++ & 0x1FF);
	struct cached_client *client = &__cached_client[index];

	memcpy(&client->from, from, sizeof(*from));
	client->flags = 1;
	client->l_ident = htons(dnsp->q_ident);
	client->r_ident = (rand() & 0xFE00) | index;
	dnsp->q_ident = htons(client->r_ident);
	return 1;
}

int send_out_ip2udp(int lowfd, unsigned char *packet, size_t length)
{
	int len, err;
	socklen_t ttl;
	struct iphdr *ip;
	struct udphdr *udp;
	struct sockaddr_in sa;

	ip = (struct iphdr *)packet;
	if (ip->protocol == IPPROTO_UDP) {
		udp = (struct udphdr *)(ip + 1);
		if (udp->dest == htons(53)) {
			sa.sin_family = AF_INET;
			sa.sin_port   = udp->source;
			sa.sin_addr.s_addr = ip->saddr;

			len = packet + length - (unsigned char *)(udp + 1);
			if (ip->ttl > 1 && record_dns_packet(udp + 1, len, &sa)) {
				sa.sin_port   = udp->dest;
				sa.sin_addr.s_addr = ip->daddr;
				ttl = (ip->ttl - 1);
				err = setsockopt(lowfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

				err = sendto(lowfd, udp + 1, len, 0, (struct sockaddr *)&sa, sizeof(sa));
				return 1;
			}
		}
	}

	return 0;
}
