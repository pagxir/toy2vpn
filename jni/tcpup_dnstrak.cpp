#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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

#ifdef __ANDROID__
	error = setsockopt(tunnel, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    assert(error == 0);
#endif

	error = bind(tunnel, (struct sockaddr *)addrp, sizeof(*addrp));
    fprintf(stderr, "bind to %s\n", inet_ntoa(addrp->sin_addr));
    assert(error == 0);

	return tunnel;
}

struct udpuphdr {
	int u_conv;

	u_char	u_flag;
	u_char	u_magic;

	u_char	u_frag;
	u_char	u_doff;
};

struct udpuphdr4 {
	struct udpuphdr uh;
	u_char tag;
	u_char len;
	u_short port;
	u_int addr[1];
};

struct udpuphdr6 {
	struct udpuphdr uh;
	u_char tag;
	u_char len;
	u_short port;
	u_int addr[4];
};

struct udpup_info {
	int is_ipv6;
	int u_conv;
	int u_port;
	long u_rcvtime;

	union {
		struct in_addr in;
		struct in6_addr in6;
	} from;

	struct udpup_info *next;
};

static struct udpup_info *_udpup_info_header = NULL;


static int _uot_udp = 0;
static int _uot_pid = 0;
static int _uot_inc = 0;
extern long ts_get_ticks();

static int upid_gen()
{
    if (_uot_pid == 0)
        _uot_pid = (ts_get_ticks() << 24);

    return _uot_pid | (_uot_inc++ & 0xff) | (random() & 0xffff) << 8;
}

struct udpup_info * udpinfo_lookup(int conv)
{
	struct udpup_info *up;

	for (up = _udpup_info_header; up != NULL; up = up->next) {
		if (up->u_conv == conv) return up;
	}

	return NULL;
}

struct udpup_info * udpinfo_create(int ipv6, const void *local, int sport)
{
	struct udpup_info *up;
	struct udpup_info *next;
	struct udpup_info **pprev;
	long current = ts_get_ticks();

	pprev = &_udpup_info_header;
	for (up = _udpup_info_header; up != NULL; up = next) {
		next = up->next;

		if (up->u_rcvtime + 15000 < current) {
			*pprev = up->next;
			_uot_udp--;
			delete up;
			continue;
		}

		if (up->u_port != sport) {
			pprev = &up->next;
			continue;
		}

		if (ipv6 && memcmp(&up->from.in6, local, 16)) {
			pprev = &up->next;
			continue;
		}

		if (!ipv6 && memcmp(&up->from.in, local, 4)) {
			pprev = &up->next;
			continue;
		}

		return up;
	}

	up = new udpup_info;
	if (up != NULL) {
		up->u_conv = upid_gen();
		up->is_ipv6 = ipv6;
		up->u_port = sport;
		up->u_rcvtime = current;

		if (ipv6) {
			memcpy(&up->from.in6, local, 16);
		} else {
			memcpy(&up->from.in, local, 4);
		}

		up->next = _udpup_info_header;
		_udpup_info_header = up;
		_uot_udp++;
	}

	return up;
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

    union {
        struct sockaddr sa; 
        struct sockaddr_in in0;
    } dest;
} __cached_client[512];

static int __last_index = 0;
int resolved_udp_packet(void *buf, const void *packet, size_t length, struct sockaddr_in *from)
{
	struct iphdr *ip;
	struct udphdr *udp;

	struct udpuphdr *puhdr;
	struct udpuphdr6 *puhdr6;

	puhdr = (struct udpuphdr *)packet;
	if (puhdr->u_flag == 0 && puhdr->u_magic == 0xcc && puhdr->u_frag == 0) {
		ip = (struct iphdr *)buf;
		udp = (struct udphdr *)(ip + 1);

		int doff = (puhdr->u_doff << 2);
		struct udpuphdr4 *puhdr4 = (struct udpuphdr4 *)puhdr;
		struct udpup_info *info = udpinfo_lookup(puhdr->u_conv);

		if (info != NULL && doff < length && info->is_ipv6 == 0) {
			memcpy(udp + 1, (char *)packet + doff, length - doff);
			length -= doff;

			udp->len = htons(length + sizeof(*udp));
			udp->check = 0;
			udp->source = puhdr4->port;
			udp->dest   = info->u_port;
			udp_checksum(&udp->check, (in_addr *)&puhdr4->addr[0],
					&info->from.in, udp, length + sizeof(*udp));

			ip->ihl = 5;
			ip->version = 4;
			ip->tos = 0;
			ip->tot_len = htons(length + (char *)(udp + 1) - (char *)buf);
			ip->id  = (0xffff & (long)ip);
			ip->frag_off = htons(0x4000);
			ip->ttl = 8;
			ip->protocol = IPPROTO_UDP;
			ip->check = 0;

			ip->saddr = puhdr4->addr[0];
			ip->daddr = info->from.in.s_addr;
			ip_checksum(&ip->check, ip, sizeof(*ip));

			return length + (char *)(udp + 1) - (char *)buf;
		}
	}

	return 0;
}

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
			udp->source = client->dest.in0.sin_port;
			udp->dest   = client->from.in0.sin_port;
			udp_checksum(&udp->check, &client->dest.in0.sin_addr,
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

			ip->saddr = client->dest.in0.sin_addr.s_addr;
			ip->daddr = client->from.in0.sin_addr.s_addr;
			ip_checksum(&ip->check, ip, sizeof(*ip));

			return length + (char *)(udp + 1) - (char *)buf;
		}
	}

	return 0;
}

int record_dns_packet(void *packet, size_t length, struct sockaddr_in *from, struct sockaddr_in *to)
{
	int flags;
	struct dns_query_packet *dnsp;

	dnsp = (struct dns_query_packet *)packet;
	flags = ntohs(dnsp->q_flags);

	if (flags & 0x8000) {
		return 0;
	}

	/* from dns client */;
	int index = (__last_index++ & 0x1FF);
	struct cached_client *client = &__cached_client[index];

	memcpy(&client->from, from, sizeof(*from));
	memcpy(&client->dest, to, sizeof(*to));
	client->flags = 1;
	client->l_ident = htons(dnsp->q_ident);
	client->r_ident = (rand() & 0xFE00) | index;
	dnsp->q_ident = htons(client->r_ident);
	return 1;
}

const char * dns_extract_name(char * name, size_t namlen,
		const char * dnsp, const char * finp, char *packet)
{
	int partlen;
	char nouse = '.';
	char * lastdot = &nouse;

	char *savp = name;
	if (dnsp == finp)
		return finp;

	/* int first = 1; */
	partlen = (unsigned char)*dnsp++;
	while (partlen) {
		unsigned short offset = 0;

		if (partlen & 0xC0) {
			offset = ((partlen & 0x3F) << 8);
			offset = (offset | (unsigned char )*dnsp++);
			if (packet != NULL) {
				/* if (first == 0) { *name++ = '.'; namlen--; } */
				dns_extract_name(name, namlen, packet + offset, packet + offset + 64, NULL);
				lastdot = &nouse;
			}
			break;
		}

		if (dnsp + partlen > finp)
			return finp;

		if (namlen > partlen + 1) {
			memcpy(name, dnsp, partlen);
			namlen -= partlen;
			name += partlen;
			dnsp += partlen;

			lastdot = name;
			*name++ = '.';
			namlen--;
		}

		if (dnsp == finp)
			return finp;
		partlen = (unsigned char)*dnsp++;
		/* first = 0; */
	}

	*lastdot = 0;
	return dnsp;
}

const char * dns_extract_value(void * valp, size_t size,
		const char * dnsp, const char * finp)
{
	if (dnsp + size > finp)
		return finp;

	memcpy(valp, dnsp, size);
	dnsp += size;
	return dnsp;
}

int is_dns_query_v6(unsigned char *packet, size_t len)
{
	char name[512];
	const char *queryp;
	const char *finishp;

	int isipv6 = 0;
	unsigned short type, dnscls;
	struct dns_query_packet *dnsp;

	dnsp = (struct dns_query_packet *)packet;

	queryp = (char *)(dnsp + 1);
	finishp = (char *)(packet + len);

	for (int i = 0; !isipv6 && i < dnsp->q_qdcount; i++) {
		dnscls = type = 0;
		queryp = dns_extract_name(name, sizeof(name), queryp, finishp, (char *)dnsp);
		queryp = dns_extract_value(&type, sizeof(type), queryp, finishp);
		queryp = dns_extract_value(&dnscls, sizeof(dnscls), queryp, finishp);
		isipv6 = (dnscls == htons(0x01) && type == htons(28));
	}

	fprintf(stderr, "isipv6 %s %d\n", name, isipv6);
	return isipv6;
}

int send_out_ip2udp(int lowfd, unsigned char *packet, size_t length)
{
	int len, err;
	socklen_t ttl;
	struct iphdr *ip;
	struct udphdr *udp;
	struct sockaddr_in sa, da;

	ip = (struct iphdr *)packet;
	if (ip->protocol == IPPROTO_UDP) {
		udp = (struct udphdr *)(ip + 1);
		if (udp->dest == htons(53)) {
			sa.sin_family = AF_INET;
			sa.sin_port   = udp->source;
			sa.sin_addr.s_addr = ip->saddr;

			da.sin_family = AF_INET;
			da.sin_port   = udp->dest;
			da.sin_addr.s_addr = ip->daddr;

			len = packet + length - (unsigned char *)(udp + 1);
			if (ip->ttl > 1
					&& !is_dns_query_v6((unsigned char *)(udp + 1), len)
					&& record_dns_packet(udp + 1, len, &sa, &da)) {
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

int fill_out_ip2udp(char *buf, unsigned char *packet, size_t length, unsigned int *pmagic)
{
	int len, err;
	int is_ipv6 = 1;
	socklen_t ttl;

	struct iphdr *ip;
	struct ip6_hdr *ip6;

	struct udphdr *udp;
	struct sockaddr_in sa, da;
	struct udpup_info *info = NULL;

	ip = (struct iphdr *)packet;
	switch (ip->version) {
		case 0x06:
			ip6 = (struct ip6_hdr *)ip;
			udp = (struct udphdr *)(ip6 + 1);
			if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP) {
				return 0;
			}

			break;

		case 0x04:
			/* version 4 */
			is_ipv6 = 0;
			udp = (struct udphdr *)(ip + 1);
			if (ip->protocol != IPPROTO_UDP) {
				return 0;
			}

			break;

		default:
			return 0;
	}

	if (is_ipv6 == 0 && udp->dest == htons(53)) {
		sa.sin_family = AF_INET;
		sa.sin_port   = udp->source;
		sa.sin_addr.s_addr = ip->saddr;

		da.sin_family = AF_INET;
		da.sin_port   = udp->dest;
		da.sin_addr.s_addr = ip->daddr;

		len = packet + length - (unsigned char *)(udp + 1);
		if (ip->ttl > 1 && record_dns_packet(udp + 1, len, &sa, &da)) {
#if 0
			sa.sin_port   = udp->dest;
			sa.sin_addr.s_addr = ip->daddr;
			ttl = (ip->ttl - 1);
			err = setsockopt(lowfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

			err = sendto(lowfd, udp + 1, len, 0, (struct sockaddr *)&sa, sizeof(sa));
			return 1;
#endif
			*pmagic = htonl(0xfe800000);
			memcpy(buf, udp + 1, len);
			return len;
		}
	} else {
		struct udpuphdr *puhdr;
		struct udpuphdr4 *puhdr4;
		struct udpuphdr6 *puhdr6;

		puhdr = (struct udpuphdr *)buf;
		puhdr->u_conv = 0xf6e7d8c9;
		puhdr->u_flag = 0;
		puhdr->u_magic = 0xCC;
		puhdr->u_frag = 0;
		puhdr->u_doff = (sizeof(*puhdr) >> 2);

		len = packet + length - (unsigned char *)(udp + 1);

		if (is_ipv6) {
			info = udpinfo_create(is_ipv6, &ip6->ip6_src, udp->source);
			if (info == NULL) return 0;

			puhdr6 = (struct udpuphdr6 *)buf;
			puhdr->u_doff = (sizeof(*puhdr6) >> 2);
			memcpy(puhdr6->addr, &ip6->ip6_dst, 16);
			puhdr6->port = udp->dest;
			puhdr6->tag  = 0x86;
			puhdr6->len  = 20;
			puhdr6->uh.u_conv = info->u_conv;
			info->u_rcvtime = ts_get_ticks();

			memcpy(puhdr6 + 1, udp + 1, len);
			*pmagic = htonl(0xfe800001);
			return len + sizeof(*puhdr6);
		} else {
			info = udpinfo_create(is_ipv6, &ip->saddr, udp->source);
			if (info == NULL) return 0;

			puhdr4 = (struct udpuphdr4 *)buf;
			puhdr->u_doff = (sizeof(*puhdr4) >> 2);
			memcpy(puhdr4->addr, &ip->daddr, 4);
			puhdr4->port = udp->dest;
			puhdr4->tag  = 0x84;
			puhdr4->len  = 8;
			puhdr4->uh.u_conv = info->u_conv;
			info->u_rcvtime = ts_get_ticks();

			memcpy(puhdr4 + 1, udp + 1, len);
			*pmagic = htonl(0xfe800001);
			return len + sizeof(*puhdr4);
		}
	}

	return 0;
}
