#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include <time.h>
#include <assert.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

#include "tcpup/up.h"
#include "tcpup/ip.h"
#include "tcpup/fsm.h"
#include "tcpup/crypt.h"
#include "tcpup/contrak.h"

#define SEQ_GEQ(a,b)     ((int)((a)-(b)) >= 0)
#define SEQ_GT(a,b)      ((int)((a)-(b)) > 0)

struct tcpup_info {
	int t_conv;
	int t_xdat;
	int t_state;
	int x_state;
	int t_wscale; //linux default is 7
	long t_rcvtime;

	u_short s_port;
	u_short d_port;

	union {
		struct in_addr in;
		struct in6_addr in6;
	} t_from, t_peer;
	int ip_ver;

	tcp_seq rcv_una;
	tcp_seq snd_una;
	tcp_seq snd_nxt;
	tcp_seq snd_max;

	tcp_seq t_irs;
	tcp_seq t_iss;

	int t_mrked;
	int t_xdat1;
	tcp_seq ts_mark;

	struct tcpup_info *next;

	int last_rcvcnt;
	struct tcpuphdr savl;
};

static int _tot_tcp = 0;
static int _tot_pid = 0;
static int _tot_inc = 0;
static struct tcpup_info *_tcpup_info_header = NULL;
static unsigned char ip6_prefix[16] = {0x20, 0x01, 0xc0, 0xa8, 0x2b, 0x01};

static char const * const tcpstates[] = { 
	"CLOSED",       "LISTEN",       "SYN_SENT",     "SYN_RCVD",
	"ESTABLISHED",  "CLOSE_WAIT",   "FIN_WAIT_1",   "CLOSING",
	"LAST_ACK",     "FIN_WAIT_2",   "TIME_WAIT",
};

long ts_get_ticks(void)
{
	int error;
	struct timespec t0;

	error = clock_gettime(CLOCK_MONOTONIC, &t0);
	if (error == 0) {
		return t0.tv_sec * 1000 + t0.tv_nsec / 1000000;
	}

	return -1;
}

static long second2ticks(int nsec)
{
	return nsec * 1000;
}

static void tcp_state_update(struct tcpup_info *upp, int state)
{
	fprintf(stderr, "%x/%-4d  %s\t -> %s\n",
			upp->t_conv, _tot_tcp, tcpstates[upp->t_state], tcpstates[state]);

	if (SEQ_GT(upp->snd_nxt, upp->snd_max)) {
		/* update snd max to nxt */
		upp->snd_max = upp->snd_nxt;
	}

	upp->t_state = state;
	upp->x_state = state;
	return;
}

static void tcp_state_preload(struct tcpup_info *upp, int state, tcp_seq ack_seq)
{
	if (upp->x_state != state) {
		fprintf(stderr, "%x/%-4d  %s\t -= %s\n",
				upp->t_conv, _tot_tcp, tcpstates[upp->t_state], tcpstates[state]);
		upp->rcv_una = ack_seq;
		upp->x_state = state;
	}

	return;
}

static int tcpup_state_send(struct tcpup_info *upp, struct tcpiphdr *tcp, size_t dlen)
{
	int xflags = 0;

	if (tcp->th_flags & TH_RST) {
		upp->t_state = TCPS_CLOSED;
		return 0;
	}

	if (upp->x_state != upp->t_state
			&& (tcp->th_flags & TH_ACK)
			&& SEQ_GEQ(htonl(tcp->th_ack), upp->rcv_una)) {
		tcp_state_update(upp, upp->x_state);
		upp->t_state = upp->x_state;
	}

	switch (upp->t_state) {
		case TCPS_CLOSED:
			xflags = TH_SYN| TH_ACK;
			if ((tcp->th_flags & xflags) == TH_SYN) {
				upp->snd_nxt = htonl(tcp->th_seq) + 1;
				upp->snd_max = htonl(tcp->th_seq) + 1;
				upp->snd_una = htonl(tcp->th_seq) + 1;
				tcp_state_update(upp, TCPS_SYN_SENT);
				return 0;
			}
			break;

		case TCPS_SYN_RECEIVED:
			assert((tcp->th_flags & TH_FIN) != TH_FIN);
			xflags = TH_SYN| TH_ACK;
			if ((tcp->th_flags & xflags) == TH_ACK
					&& SEQ_GT(htonl(tcp->th_seq), upp->snd_nxt)) {
				tcp_state_update(upp, upp->x_state);
				return 0;
			}
			break;

		case TCPS_ESTABLISHED:
			if ((tcp->th_flags & TH_FIN) == TH_FIN) {
				upp->snd_nxt = htonl(tcp->th_seq) + dlen + 1;
				tcp_state_update(upp, TCPS_FIN_WAIT_1);
				return 0;
			}
			break;

		case TCPS_CLOSE_WAIT:
			if ((tcp->th_flags & TH_FIN) == TH_FIN) {
				upp->snd_nxt = htonl(tcp->th_seq) + dlen + 1;
				tcp_state_update(upp, TCPS_LAST_ACK);
				return 0;
			}
			break;

		case TCPS_FIN_WAIT_1:
			xflags = TH_FIN| TH_ACK;
			if ((tcp->th_flags & xflags) == TH_ACK) {
				tcp_state_update(upp, upp->x_state);
				return 0;
			}
			break;
	}

	if (dlen > 0) {
		upp->snd_nxt = htonl(tcp->th_seq) + dlen;
		if (SEQ_GT(upp->snd_nxt, upp->snd_max)) {
			/* update snd max to nxt */
			upp->snd_max = upp->snd_nxt;
		}
	}

	return 0;
}

static int tcpup_state_receive(struct tcpup_info *upp, struct tcpiphdr *tcp, size_t dlen)
{
	int xflags = 0;
	int snd_una = htonl(tcp->th_ack);

	if (tcp->th_flags & TH_RST) {
		upp->t_state = TCPS_CLOSED;
		return 0;
	}

	if ((tcp->th_flags & TH_ACK) && SEQ_GT(snd_una, upp->snd_una)) {
		/* update snd una from peer */
		upp->snd_una = snd_una;
	}

	switch (upp->t_state) {
		case TCPS_SYN_SENT:
			xflags = TH_SYN| TH_ACK;
			if ((tcp->th_flags & xflags) == TH_SYN) {
				assert((tcp->th_flags & TH_FIN) != TH_FIN);
				tcp_state_preload(upp, TCPS_SYN_RECEIVED, htonl(tcp->th_seq) + 1);
				return 0;
			}

			if ((tcp->th_flags & xflags) == xflags
					&& SEQ_GEQ(htonl(tcp->th_ack), upp->snd_nxt)) {
				assert((tcp->th_flags & TH_FIN) != TH_FIN);
				tcp_state_preload(upp, TCPS_ESTABLISHED, htonl(tcp->th_seq));
				return 0;
			}
			break;

		case TCPS_SYN_RECEIVED:
			if ((tcp->th_flags & TH_ACK) == TH_ACK
					&& SEQ_GEQ(htonl(tcp->th_ack), upp->snd_nxt)) {
				assert((tcp->th_flags & TH_FIN) != TH_FIN);
				tcp_state_preload(upp, TCPS_ESTABLISHED, htonl(tcp->th_seq));
				return 0;
			}
			break;

		case TCPS_ESTABLISHED:
			if ((tcp->th_flags & TH_FIN) == TH_FIN) {
				tcp_state_preload(upp, TCPS_CLOSE_WAIT, htonl(tcp->th_seq) + 1);
				return 0;
			}
			break;

		case TCPS_FIN_WAIT_1:
			xflags = TH_FIN| TH_ACK;
			if ((tcp->th_flags & xflags) == xflags
					&& SEQ_GEQ(htonl(tcp->th_ack), upp->snd_nxt)) {
				tcp_state_preload(upp, TCPS_TIME_WAIT, htonl(tcp->th_seq) + dlen + 1);
				return 0;
			}

			if ((tcp->th_flags & TH_FIN) == TH_FIN) {
				tcp_state_preload(upp, TCPS_CLOSING, htonl(tcp->th_seq) + dlen + 1);
				return 0;
			}

			if ((tcp->th_flags & TH_ACK) == TH_ACK
					&& SEQ_GEQ(htonl(tcp->th_ack), upp->snd_nxt)) {
				tcp_state_preload(upp, TCPS_FIN_WAIT_2, htonl(tcp->th_seq) + dlen);
				return 0;
			}
			break;

		case TCPS_FIN_WAIT_2:
			if ((tcp->th_flags & TH_FIN) == TH_FIN) {
				tcp_state_preload(upp, TCPS_TIME_WAIT, htonl(tcp->th_seq) + dlen + 1);
				return 0;
			}
			break;

		case TCPS_CLOSING:
			if ((tcp->th_flags & TH_ACK) == TH_ACK
					&& SEQ_GEQ(htonl(tcp->th_ack), upp->snd_nxt)) {
				tcp_state_preload(upp, TCPS_TIME_WAIT, htonl(tcp->th_seq) + dlen);
				return 0;
			}
			break;

		case TCPS_LAST_ACK:
			if ((tcp->th_flags & TH_ACK) == TH_ACK
					&& SEQ_GEQ(htonl(tcp->th_ack), upp->snd_nxt)) {
				tcp_state_preload(upp, TCPS_CLOSED, htonl(tcp->th_seq) + dlen);
				return 0;
			}
			break;

		case TCPS_TIME_WAIT:
			fprintf(stderr, "before TIME_WAIT -> TIME_WAIT\n");
			break;
	}

	return 0;
}

static tcpup_info *tcpup_findcb(int src, int dst, u_short sport, u_short dport)
{
	struct tcpup_info *tp;

	for (tp = _tcpup_info_header; tp; tp = tp->next) {
		if (tp->s_port != sport ||
				tp->d_port != dport) {
			continue;
		}

		if (tp->t_from.in.s_addr != src ||
				tp->t_peer.in.s_addr != dst) {
			continue;
		}

		return tp;
	}

	return 0;
}

static tcpup_info *tcpup_findcb6(const struct in6_addr &src, const struct in6_addr &dst, u_short sport, u_short dport)
{
	struct tcpup_info *tp;

	for (tp = _tcpup_info_header; tp; tp = tp->next) {
		if (tp->s_port != sport ||
				tp->d_port != dport) {
			continue;
		}

		if (memcmp(&tp->t_from, &src, sizeof(src)) ||
				memcmp(&tp->t_peer, &dst, sizeof(dst))) {
			continue;
		}

		return tp;
	}

	return 0;
}

static tcpup_info *tcpup_lookup(uint32_t conv)
{
	long now;
	struct tcpup_info *tp;
	struct tcpup_info *tp_next;
	struct tcpup_info **tp_prev = &_tcpup_info_header;

	now = ts_get_ticks();
	for (tp = _tcpup_info_header; tp; tp = tp_next) {
		if (tp->t_conv == conv) {
			tp->t_rcvtime = now;
			return tp;
		}

		tp_next = tp->next;
		switch (tp->t_state) {
			case TCPS_CLOSED:
				*tp_prev = tp->next;
				_tot_tcp--;
				delete tp;
				continue;

			case TCPS_LAST_ACK:
			case TCPS_TIME_WAIT:
				if (tp->t_rcvtime + second2ticks(6) <= now) {
					*tp_prev = tp->next;
					_tot_tcp--;
					delete tp;
					continue;
				}
				break;

			default:
				if (tp->t_rcvtime + second2ticks(120) <= now) {
					*tp_prev = tp->next;
					_tot_tcp--;
					delete tp;
					continue;
				}
				break;
		}

		tp_prev = &tp->next;
	}

	return 0;
}

static tcpup_info *tcpup_newcb(int src, int dst, u_short sport, u_short dport)
{
	struct tcpup_info *up = new tcpup_info;
	assert(up != NULL);
	tcpup_lookup(-1);
	memset(up, 0, sizeof(*up));

	if (_tot_pid == 0)
		_tot_pid = (ts_get_ticks() << 24);

	up->t_conv = _tot_pid | (_tot_inc++ & 0xff) | (random() & 0xffff) << 8;

	up->t_from.in.s_addr = src;
	up->t_peer.in.s_addr = dst;
	up->s_port = sport;
	up->d_port = dport;
	up->t_state = TCPS_CLOSED;
	up->x_state = TCPS_CLOSED;
	up->t_wscale = 7;
	up->t_rcvtime = ts_get_ticks();
	up->t_xdat  = rand();
	up->ip_ver  = 0x04;

	up->t_mrked = 0;
	up->ts_mark = 0;
	up->t_xdat1 = rand();
	up->last_rcvcnt = 0;

	up->next = _tcpup_info_header;
	_tcpup_info_header = up;
	_tot_tcp++;

	return up;
}

static tcpup_info *tcpup_newcb6(const struct in6_addr &src, const struct in6_addr &dst, u_short sport, u_short dport)
{
	struct tcpup_info *up = tcpup_newcb(0, 0, sport, dport);
	assert(up != NULL);

	up->t_from.in6 = src;
	up->t_peer.in6 = dst;
	up->ip_ver  = 0x06;

	return up;
}

static tcpup_info *tcpup_wrapcb(struct tcpup_info *local, unsigned relayip, unsigned relaymask, u_short port)
{
	static struct tcpup_info info0;

	if (local != NULL && local->ip_ver == 0x04) {
		unsigned int subnet = relayip & ~relaymask;

		unsigned short sport = (local->t_conv & 0xffff);
		unsigned int sclient = subnet | ((local->t_conv >> 16)  & 0xffff);

		info0 = *local;

		info0.t_peer.in.s_addr = htonl(sclient); 
		info0.d_port = sport;

		info0.t_from.in.s_addr = relayip;
		info0.s_port = port;

		return &info0;
	}

	if (local != NULL && local->ip_ver == 0x06) {
		unsigned int subnet = relayip & ~relaymask;

		unsigned short sport = (local->t_conv & 0xffff);
		unsigned int sclient = subnet | ((local->t_conv >> 16)  & 0xffff);

		info0 = *local;

		info0.t_peer.in.s_addr = htonl(sclient); 
		info0.d_port = sport;

		info0.t_from.in.s_addr = relayip;
		info0.s_port = port;

		info0.ip_ver = 0x04;
		return &info0;
	}

	return NULL;
}

static u_char _null_[28] = {0};
static u_char type_len_map[8] = {0x0, 0x04, 0x0, 0x0, 0x10};

static int set_relay_info(u_char *target, int type, void *host, u_short port)
{
	int len;
	char *p, buf[60];

	p = (char *)target;
	*p++ = (type & 0xff);
	*p++ = 0;

	memcpy(p, &port, 2); 
	p += 2;

	len = type_len_map[type & 0x7];
	memcpy(p, host, len);
	p += len;

	return p - (char *)target;
}

static int translate_tcpip(struct tcpup_info *info, struct tcpuphdr *field, struct tcpiphdr *tcp, int length, unsigned char **fakeack)
{
	int cnt;
	int offip, offup;
	u_char *dst, *src = 0;
	struct tcpupopt to = {0};

	field->th_seq = tcp->th_seq;
	field->th_ack = tcp->th_ack;
	field->th_magic = MAGIC_UDP_TCP;

	field->th_win   = tcp->th_win;
	field->th_flags = tcp->th_flags;

	cnt = (tcp->th_off << 2);
	src = (u_char *)(tcp + 1);
	dst = (u_char *)(field + 1);

	offip = tcpip_dooptions(&to, src, cnt - sizeof(*tcp));
	if (tcp->th_flags & TH_SYN) {
		to.to_flags |= TOF_DESTINATION;
		to.to_dslen  = set_relay_info(_null_, info->ip_ver == 0x04? 0x01: 0x04, &info->t_peer, info->d_port);
		to.to_dsaddr = _null_;

		if (to.to_flags & TOF_SCALE) {
			/* TODO: wscale will be not 7 */
			info->t_wscale = to.to_wscale;
		}
	}

	if (to.to_flags & TOF_TS) {
		field->th_tsecr = htonl(to.to_tsecr);
		field->th_tsval = htonl(to.to_tsval);
	}

#if 0
	if (info->t_mrked == 0) {
		info->ts_mark = htonl(field->th_tsval);
		info->t_mrked = 1;
	}
#endif

	if (info->t_wscale != 7) {
		/* convert windows scale from old to new */
		unsigned int win = htons(tcp->th_win) << info->t_wscale;
		field->th_win = htons(win >> 7);
	}

	offup = tcpup_addoptions(&to, dst);
	field->th_opten = (offup >> 2);

	cnt = length - offip - sizeof(*tcp);
	assert(cnt >= 0);
	memcpy(dst + offup, src + offip, cnt);

	int th_ack = htonl(tcp->th_ack);

	if (SEQ_GT(th_ack, info->snd_una)
			&& cnt == 0 && to.to_nsacks == 0
			&& (tcp->th_flags == TH_ACK) && offup == 0
			&& ((int)(th_ack - info->snd_una) > 1460)) {
		static unsigned char fake[1500];
		struct tcpuphdr *p = (struct tcpuphdr *)fake;
		memcpy(fake, field, sizeof(*field));
		p->th_conv  = info->t_conv;
		p->th_flags = 0;
		*fakeack = fake;
	}

	tcpup_state_send(info, tcp, cnt);

	return cnt + sizeof(*field) + offup;
}

static int translate_tcpup(struct tcpup_info *upp, struct tcpiphdr *tcp, struct tcpuphdr *field, int length)
{
	int cnt;
	int offip, offup;
	u_char *dst, *src = 0;
	struct tcpupopt to = {0};

	tcp->th_seq = field->th_seq;
	tcp->th_ack = field->th_ack;
	tcp->th_win  = field->th_win;
	tcp->th_flags  = field->th_flags;

	cnt = (field->th_opten << 2);
	src = (u_char *)(field + 1);
	dst = (u_char *)(tcp + 1);

	offup = tcpup_dooptions(&to, src, cnt);
	to.to_flags |= TOF_TS;
	to.to_tsval  = htonl(field->th_tsval);
	to.to_tsecr  = htonl(field->th_tsecr);

	if (tcp->th_flags & TH_SYN) {
		to.to_wscale = 7;
		to.to_flags |= TOF_SCALE;
		to.to_flags |= TOF_SACKPERM;
	}

	offip = tcpip_addoptions(&to, dst);
	tcp->th_off    = (sizeof(*tcp) + offip) >> 2;
	tcp->th_x2     = 0;
	tcp->th_urp    = 0;

	cnt = length - offup;
	assert(cnt >= 0);
	memcpy(dst + offip, ((char *)field) + offup, cnt);

	if ((cnt > 0) || 
			(tcp->th_flags & TH_PUSH)) {
		upp->last_rcvcnt = cnt;
	}

	return cnt + sizeof(*tcp) + offip;
}

int translate_ip2up(unsigned char *buf, size_t size, unsigned char *packet, size_t length, int *pxdat, unsigned char **fakeack)
{
	int offset;
	int is_ipv6 = 1;

	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct tcpiphdr *tcp;
	struct tcpup_info *upp = NULL;

	ip = (struct iphdr *)packet;

	switch (ip->version) {
		case 0x06:
			ip6 = (struct ip6_hdr *)packet;
			tcp = (struct tcpiphdr *)(ip6 + 1);
			if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
				fprintf(stderr, "drop6, protocol not support: %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
				return 0;
			}
			upp = tcpup_findcb6(ip6->ip6_src, ip6->ip6_dst, tcp->th_sport, tcp->th_dport);
			break;

		case 0x04:
			is_ipv6 = 0;
			tcp = (struct tcpiphdr *)(ip + 1);
			if (ip->protocol != IPPROTO_TCP) {
				fprintf(stderr, "drop, protocol not support: %d\n", ip->protocol);
				return 0;
			}

			upp = tcpup_findcb(ip->saddr, ip->daddr, tcp->th_sport, tcp->th_dport);
			break;

		default:
			fprintf(stderr, "drop, family not support: %d\n", ip->version);
			is_ipv6 = 0;
			return 0;
	}


	if (upp == NULL) {
		if (tcp->th_flags & TH_RST) {
			/* silent drop, ignore packet */
			fprintf(stderr, "silent drop, ignore packet\n");
			return 0;
		}

		if (tcp->th_flags & TH_ACK) {
			/* send back rst */
			fprintf(stderr, "send back rst, but ignore\n");
			return -1;
		}

		if (tcp->th_flags & TH_SYN) {
			fprintf(stderr, "tcpup connect context is created\n");
			upp = (is_ipv6 == 0)?
				tcpup_newcb(ip->saddr, ip->daddr, tcp->th_sport, tcp->th_dport):
				tcpup_newcb6(ip6->ip6_src, ip6->ip6_dst, tcp->th_sport, tcp->th_dport);
			assert(upp != NULL);
		} else {
			/* silent drop, ignore packet */
			fprintf(stderr, "silent drop, ignore packet\n");
			return 0;
		}
	}

	struct tcpuphdr *uphdr = (struct tcpuphdr *)buf;
	offset = translate_tcpip(upp, uphdr, tcp, packet + length - (unsigned char *)tcp, fakeack);
	uphdr->th_conv = upp->t_conv;

	if (upp->snd_una == upp->snd_max) {
		long ticks = ts_get_ticks();
		if (ticks > upp->t_rcvtime + second2ticks(5)/10) {
			if (upp->t_mrked == 0) {
				upp->ts_mark = htonl(uphdr->th_tsval);
				upp->t_xdat  = rand();
				upp->t_mrked = 1;
			}
		}
	}

	memcpy(&upp->savl, uphdr, sizeof(*uphdr));

	*pxdat = upp->t_xdat;
	return offset;
}

int tcp_reset_fill(unsigned char *buf, unsigned char *packet, size_t length)
{
	int isv6 = 1;
	struct iphdr *ip;
	struct iphdr *ip1;
	struct ip6_hdr *ip6;
	struct ip6_hdr *ip6x;
	struct tcpiphdr *tcp;
	struct tcpiphdr *tcp1;
	struct in_addr saddr, daddr;

	ip1 = (struct iphdr *)packet;
	switch (ip1->version) {
		case 0x04:
			isv6 = 0;
			tcp1 = (struct tcpiphdr *)(ip1 + 1);
			break;

		case 0x06:
			ip6x = (struct ip6_hdr *)packet;
			tcp1 = (struct tcpiphdr *)(ip6x + 1);
			break;

		default:
			isv6 = 0;
			return 0;
	}

	if (isv6) {
		ip6 = (struct ip6_hdr *)buf;
		tcp = (struct tcpiphdr *)(ip6 + 1);

		ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
		ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(*tcp));

		ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
		ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 10;

		ip6->ip6_src = ip6x->ip6_dst;
		ip6->ip6_dst = ip6x->ip6_src;
	} else {
		ip = (struct iphdr *)buf;
		tcp = (struct tcpiphdr *)(ip + 1);

		ip->ihl = 5;
		ip->version = 4;
		ip->tos = 0;
		ip->tot_len = htons(sizeof(*tcp) + sizeof(*ip));
		ip->id  = (0xffff & (long)ip);
		ip->frag_off = htons(0x4000);
		ip->ttl = 28;
		ip->protocol = IPPROTO_TCP;
		ip->check = 0;

		ip->saddr = ip1->daddr;
		ip->daddr = ip1->saddr;
	}

	tcp->th_dport = tcp1->th_sport;
	tcp->th_sport = tcp1->th_dport;
	tcp->th_sum   = 0;

	if (tcp1->th_flags & TH_SYN) {
		tcp->th_seq = 0;
		tcp->th_ack = htonl(htonl(tcp1->th_seq) + 1);
		tcp->th_win  = 0;
		tcp->th_flags  = (TH_ACK | TH_RST);
	} else if (tcp1->th_flags & TH_ACK) {
		tcp->th_seq = tcp1->th_ack;
		tcp->th_ack = 0;
		tcp->th_win  = 0;
		tcp->th_flags  = (TH_RST);
	}

	tcp->th_off    = (sizeof(*tcp) >> 2);
	tcp->th_x2     = 0;
	tcp->th_urp    = 0;

	if (isv6) {
		tcp_checksum(&tcp->th_sum, isv6, &ip6->ip6_src, &ip6->ip6_dst, tcp, sizeof(*tcp));
	} else {
		tcp_checksum(&tcp->th_sum, isv6, &ip->saddr, &ip->daddr, tcp, sizeof(*tcp));
		ip_checksum(&ip->check, ip, sizeof(*ip));
	}

	return (unsigned char *)(tcp + 1) - buf;
}

int tcpup_reset_fill(unsigned char *buf, unsigned char *packet, size_t length)
{
	struct tcpuphdr *tcp;
	struct tcpuphdr *tcp1;

	tcp = (struct tcpuphdr *)(buf);
	tcp1 = (struct tcpuphdr *)(packet);

	if (tcp1->th_flags & TH_SYN) {
		tcp->th_seq = 0;
		tcp->th_ack = htonl(htonl(tcp1->th_seq) + 1);
		tcp->th_win  = 0;
		tcp->th_flags  = (TH_ACK | TH_RST);
	} else if (tcp1->th_flags & TH_ACK) {
		tcp->th_seq = tcp1->th_ack;
		tcp->th_ack = 0;
		tcp->th_win  = 0;
		tcp->th_flags  = (TH_RST);
	}

	tcp->th_magic = MAGIC_UDP_TCP;
	tcp->th_opten = 0;
	return sizeof(*tcp);
}

struct tcpup_info * tcpup_forward(int conv, struct tcpuphdr *field)
{
	u_short port;
	unsigned daddr;

	struct tcpup_info *up = 0;
	struct tcpupopt to = {0};

	int cnt = (field->th_opten << 2);
	u_char *src = (u_char *)(field + 1);
	fprintf(stderr, "len: %x\n", cnt);
	tcpup_dooptions(&to, src, cnt);

	/*
	 * tcpup_newcb(ip->saddr, ip->daddr, tcp->th_sport, tcp->th_dport);
	 * tcpup_newcb6(ip6->ip6_src, ip6->ip6_dst, tcp->th_sport, tcp->th_dport);
	 */

	if ((to.to_flags & TOF_DESTINATION) && to.to_dsaddr[0] == 0x01) {
		memcpy(&port, to.to_dsaddr + 2, 2);
		memcpy(&daddr, to.to_dsaddr + 4, 4);
		up = tcpup_newcb(daddr, htonl(0x0A070000 | ((conv >> 16) & 0xffff)), port, (conv & 0xffff));
		if (up) up->t_conv = conv;
	} else {
		fprintf(stderr, "failure: %d %x %x\n", 999, to.to_flags, to.to_dsaddr? to.to_dsaddr[0]: 0);
	}

	return up;
}

int translate_up2ip(unsigned char *buf, size_t size, unsigned char *packet, size_t length)
{
	int offset;
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct tcpiphdr *tcp;
	struct in_addr saddr, daddr;
	struct tcpup_info *upp = NULL;
	struct tcpuphdr  *field = (struct tcpuphdr *)buf;

	field = (struct tcpuphdr *)packet;
	upp = tcpup_lookup(field->th_conv);

	if (upp == NULL) {
		if (field->th_flags & TH_RST) {
			/* silent drop, ignore packet */
			return 0;
		}

		fprintf(stderr, "%x not find %x\n", field->th_conv, field->th_magic);
		if (field->th_flags & TH_ACK) {
			fprintf(stderr, "%x send back reset 0x%x\n", field->th_conv, field->th_magic);
			return -1;
		}

		if (field->th_flags & TH_SYN) {
			upp = tcpup_forward(field->th_conv, field);
			if (upp == NULL) return 0;
		} else {
			/* !field->syn */
			/* silent drop, ignore packet */
			return 0;
		}
	}

	if (upp->ip_ver == 0x04) {
		ip = (struct iphdr *)buf;
		tcp = (struct tcpiphdr *)(ip + 1);

		ip->ihl = 5;
		ip->version = 4;
		ip->tos = 0;
		ip->id  = (0xffff & (long)ip);
		ip->tot_len = htons(sizeof(*tcp) + sizeof(*ip));
		ip->frag_off = htons(0x4000);
		ip->ttl = 28;
		ip->protocol = IPPROTO_TCP;
		ip->check = 0;

		ip->saddr = upp->t_peer.in.s_addr;
		ip->daddr = upp->t_from.in.s_addr;
	} else {
		ip6 = (struct ip6_hdr *)buf;
		tcp = (struct tcpiphdr *)(ip6 + 1);

		ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
		ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(*tcp));

		ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
		ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 10;

		ip6->ip6_src = upp->t_peer.in6;
		ip6->ip6_dst = upp->t_from.in6;
	}

	int t_xdat;
	if (upp->t_mrked &&
			SEQ_GEQ(htonl(field->th_tsecr), upp->ts_mark)) {
		upp->t_mrked = 0;
	}

	offset = translate_tcpup(upp, tcp, field, length);

	tcp->th_dport = upp->s_port;
	tcp->th_sport = upp->d_port;
	tcp->th_sum   = 0;

	if (upp->ip_ver == 0x04) {
		ip->tot_len = htons(offset + sizeof(*ip));
		tcp_checksum(&tcp->th_sum, 0, &ip->saddr, &ip->daddr, tcp, offset);
		ip_checksum(&ip->check, ip, sizeof(*ip));
	} else {
		ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(offset);
		tcp_checksum(&tcp->th_sum, 1, &ip6->ip6_src, &ip6->ip6_dst, tcp, offset);
	}

	tcpup_state_receive(upp, tcp, offset - (tcp->th_off << 2));
	return (unsigned char *)tcp + offset - buf;
}

int tcpup_do_keepalive(tcpup_out_f *output, int tunnel, int xdat)
{
	int c1, c2;
	char buf[1500];
	struct tcpuphdr *tcp;
	struct tcpup_info *tp;

	c1 = c2 = 0;
	for (tp = _tcpup_info_header; tp; tp = tp->next) {
		if (tp->last_rcvcnt > 0 &&
				tp->snd_max == tp->snd_una &&
				tp->t_rcvtime + 500 < ts_get_ticks() &&
				tp->t_rcvtime + 20000 > ts_get_ticks()) {
			tcp = &tp->savl;
			tcp->th_opten = 0;
			tcp_seq tsval = htonl(tcp->th_tsval);
			tcp->th_tsval = htonl(tsval + 1); 

			memcpy(buf, &tp->savl, sizeof(*tcp));
			tcp = (struct tcpuphdr *)buf;
			if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST)) continue;

			tcp->th_seq = htonl(tp->snd_una - 1);
#ifdef __ANDROID__
			__android_log_print(ANDROID_LOG_INFO, "TOYVPN-JNI", "keepalive %x %d", tcp->th_conv, ts_get_ticks() - tp->t_rcvtime);
#endif

			if (tp->t_rcvtime + 1000 < ts_get_ticks()) {
				if (tp->t_mrked == 0) {
					tp->ts_mark = htonl(tcp->th_tsval);
					tp->t_xdat  = rand();
					tp->t_mrked = 1;
				}
			}

			xdat = tp->t_xdat;
			output(tunnel, buf, sizeof(*tcp), xdat);
			c2++;
		}
		c1++;
	}

	return (c1 << 16) | c2;
}

static int sockv5_connect(void *buf, struct tcpup_info *xpp)
{
	if (xpp->ip_ver == 0x06) {
		char *cmdp = (char *)buf;
		*cmdp++ = 0x05;
		*cmdp++ = 0x01;
		*cmdp++ = 0x00;

		*cmdp++ = 0x05;
		*cmdp++ = 0x01;
		*cmdp++ = 0x00;
		*cmdp++ = 0x04;
		memcpy(cmdp, &xpp->t_peer.in6, 16);
		cmdp += 16;
		memcpy(cmdp, &xpp->d_port, 2);
		cmdp += 2;
		return cmdp - (char *)buf;
	} else if (xpp->ip_ver == 0x04) {
		char *cmdp = (char *)buf;
		*cmdp++ = 0x05;
		*cmdp++ = 0x01;
		*cmdp++ = 0x00;

		*cmdp++ = 0x05;
		*cmdp++ = 0x01;
		*cmdp++ = 0x00;
		*cmdp++ = 0x01;
		memcpy(cmdp, &xpp->t_peer.in, 4);
		cmdp += 4;
		memcpy(cmdp, &xpp->d_port, 2);
		cmdp += 2;
		return cmdp - (char *)buf;
	}

	return 0;
}

int translate_ip2ip(unsigned char *buf, size_t size, unsigned char *pack, size_t length, unsigned relayip, unsigned mask, u_short port)
{
	int offset;
	int is_ipv6 = 1;
	int cut_data = 0;
	struct iphdr *ip;
	struct ip6_hdr *ip6;
	struct tcpiphdr *tcp;
	struct tcpup_info *xpp = NULL;
	struct tcpup_info *upp = NULL;

	ip = (struct iphdr *)pack;

	switch (ip->version) {
		case 0x06:
			ip6 = (struct ip6_hdr *)pack;
			tcp = (struct tcpiphdr *)(ip6 + 1);
			if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP) {
				fprintf(stderr, "drop6, protocol not support: %d\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
				return 0;
			}

			{
				xpp = tcpup_findcb6(ip6->ip6_src, ip6->ip6_dst, tcp->th_sport, tcp->th_dport);
				upp = tcpup_wrapcb(xpp, relayip, mask, port);
			}
			break;

		case 0x04:
			is_ipv6 = 0;
			tcp = (struct tcpiphdr *)(ip + 1);
			if (ip->protocol != IPPROTO_TCP) {
				fprintf(stderr, "drop, protocol not support: %d\n", ip->protocol);
				return 0;
			}

			if (relayip == ip->saddr && tcp->th_sport == port) {
				unsigned int hipart = 0xffff & ntohl(ip->daddr);
				upp = tcpup_lookup((hipart << 16) | tcp->th_dport);
				if (upp == NULL) return -1;
				xpp = upp;
			} else {
				xpp = tcpup_findcb(ip->saddr, ip->daddr, tcp->th_sport, tcp->th_dport);
				upp = tcpup_wrapcb(xpp, relayip, mask, port);
			}
			break;

		default:
			fprintf(stderr, "drop, family not support: %d\n", ip->version);
			is_ipv6 = 0;
			return 0;
	}


	if (upp == NULL) {
		if (tcp->th_flags & TH_RST) {
			/* silent drop, ignore packet */
			fprintf(stderr, "silent drop, ignore packet\n");
			return 0;
		}

		if (tcp->th_flags & TH_ACK) {
			/* send back rst */
			fprintf(stderr, "send back rst, but ignore\n");
			return -1;
		}

		if (tcp->th_flags & TH_SYN) {
			xpp = (is_ipv6 == 0)?
				tcpup_newcb(ip->saddr, ip->daddr, tcp->th_sport, tcp->th_dport):
				tcpup_newcb6(ip6->ip6_src, ip6->ip6_dst, tcp->th_sport, tcp->th_dport);
			assert(xpp != NULL);
			upp = tcpup_wrapcb(xpp, relayip, mask, port);
		} else {
			/* silent drop, ignore packet */
			fprintf(stderr, "silent drop, ignore packet\n");
			return 0;
		}
	}

	if (xpp != NULL) {
		int flgmask = TH_SYN| TH_ACK| TH_RST;
		int payload = (char *)pack + length - (char *)tcp;

		if (xpp == upp) {
			if ((tcp->th_flags & flgmask) == (TH_ACK| TH_SYN)) {
				int len;
				struct iphdr *ipo;
				struct tcpiphdr *tcpo;

				ipo = (struct iphdr *)buf;
				tcpo = (struct tcpiphdr *)(ipo + 1);
				xpp->t_irs = htonl(tcp->th_seq);

				ipo->ihl = 5;
				ipo->version = 4;
				ipo->tos = 0;
				ipo->id  = (0xffff & (long)ipo);
				ipo->tot_len = htons(sizeof(*tcp) + sizeof(*ip));
				ipo->frag_off = htons(0x4000);
				ipo->ttl = 28;
				ipo->protocol = IPPROTO_TCP;

				upp = tcpup_wrapcb(xpp, relayip, mask, port);
				ipo->saddr = upp->t_peer.in.s_addr;
				ipo->daddr = upp->t_from.in.s_addr;
				ipo->check = 0;

				len = sizeof(*tcp) + sockv5_connect(tcpo + 1, xpp);
				tcpo->th_flags = TH_ACK;
				tcpo->th_seq   = tcp->th_ack;
				tcpo->th_ack   = htonl(htonl(tcp->th_seq) + 1);

				tcpo->th_off    = sizeof(*tcp) >> 2;
				tcpo->th_x2     = 0;
				tcpo->th_urp    = 0;
				tcpo->th_win    = htons(4096);

				ipo->tot_len = htons(len + sizeof(*ip));

				tcpo->th_dport = upp->s_port;
				tcpo->th_sport = upp->d_port;
				tcpo->th_sum = 0;

				fprintf(stderr, "fake response\n");
				tcp_checksum(&tcpo->th_sum, 0, &ipo->saddr, &ipo->daddr, tcpo, len);
				ip_checksum(&ipo->check, ipo, sizeof(*ipo));
				return len + sizeof(*ipo);
			} else {
				if ((tcp->th_flags & flgmask) == TH_ACK &&
						xpp->t_iss + 1 == htonl(tcp->th_ack) &&
						SEQ_GEQ(xpp->t_irs + 12, htonl(tcp->th_seq))) {
					if (SEQ_GT(htonl(tcp->th_seq) + payload - (tcp->th_off << 2), xpp->t_irs + 12)) {
						fprintf(stderr, "add ACK|SYN packet: %d\n", payload - (tcp->th_off << 2));
						tcp_seq seq = (xpp->t_irs + 12);
						tcp->th_seq = htonl(seq);
						tcp->th_flags |= TH_SYN;
						cut_data = 1;
					} else {
						int len;
						struct iphdr *ipo;
						struct tcpiphdr *tcpo;

						ipo = (struct iphdr *)buf;
						tcpo = (struct tcpiphdr *)(ipo + 1);

						ipo->ihl = 5;
						ipo->version = 4;
						ipo->tos = 0;
						ipo->id  = (0xffff & (long)ipo);
						ipo->tot_len = htons(sizeof(*tcp) + sizeof(*ip));
						ipo->frag_off = htons(0x4000);
						ipo->ttl = 28;
						ipo->protocol = IPPROTO_TCP;

						upp = tcpup_wrapcb(xpp, relayip, mask, port);
						ipo->saddr = upp->t_peer.in.s_addr;
						ipo->daddr = upp->t_from.in.s_addr;
						ipo->check = 0;

						len = sizeof(*tcp);
						tcpo->th_flags = TH_ACK;
						tcpo->th_seq   = tcp->th_ack;
						tcpo->th_ack   = htonl(htonl(tcp->th_seq) + payload - (tcp->th_off << 2));

						tcpo->th_off    = sizeof(*tcp) >> 2;
						tcpo->th_x2     = 0;
						tcpo->th_urp    = 0;
						tcpo->th_win    = htons(4096);

						ipo->tot_len = htons(len + sizeof(*ip));

						tcpo->th_dport = upp->s_port;
						tcpo->th_sport = upp->d_port;
						tcpo->th_sum = 0;

						fprintf(stderr, "fake ack\n");
						tcp_checksum(&tcpo->th_sum, 0, &ipo->saddr, &ipo->daddr, tcpo, len);
						ip_checksum(&ipo->check, ipo, sizeof(*ipo));
						fprintf(stderr, "ignore packet\n");
						return len + sizeof(*ipo);
					}
				}
				tcpup_state_receive(xpp, tcp, cut_data? 0: payload - (tcp->th_off << 2));
			}
		} else {
			if (tcp->th_flags & TH_SYN) {
				char buf[512];
				fprintf(stderr, "fake request\n");
				int ign_len = sockv5_connect(buf, xpp);
				tcp_seq seq = htonl(tcp->th_seq);
				tcp->th_seq = htonl(seq - ign_len);
				xpp->t_iss = seq;
			}
			tcpup_state_send(xpp, tcp, payload - (tcp->th_off << 2));
		}
	}

	if (upp->ip_ver == 0x06) {
		struct ip6_hdr *ipo6;
		struct tcpiphdr *tcpo;

		ipo6 = (struct ip6_hdr *)buf;
		tcpo = (struct tcpiphdr *)(ipo6 + 1);

		ipo6->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
		ipo6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(*tcpo));

		ipo6->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP;
		ipo6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 10;

		int len = (char *)pack + length - (char *)tcp;
		if (cut_data) len = (tcp->th_off << 2);
		memcpy(tcpo, tcp, len);

		ipo6->ip6_src = upp->t_peer.in6;
		ipo6->ip6_dst = upp->t_from.in6;
		tcpo->th_dport = upp->s_port;
		tcpo->th_sport = upp->d_port;

		ipo6->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(len);
		tcp_checksum(&tcpo->th_sum, 1, &ipo6->ip6_src, &ipo6->ip6_dst, tcpo, len);
		return len + sizeof(*ipo6);
	} else {
		int len;
		struct iphdr *ipo;
		struct tcpiphdr *tcpo;

		ipo = (struct iphdr *)buf;
		tcpo = (struct tcpiphdr *)(ipo + 1);

		ipo->ihl = 5;
		ipo->version = 4;
		ipo->tos = 0;
		ipo->id  = (0xffff & (long)ipo);
		ipo->tot_len = htons(sizeof(*tcp) + sizeof(*ip));
		ipo->frag_off = htons(0x4000);
		ipo->ttl = 28;
		ipo->protocol = IPPROTO_TCP;

		ipo->saddr = upp->t_peer.in.s_addr;
		ipo->daddr = upp->t_from.in.s_addr;
		ipo->check = 0;

		len = (char *)pack + length - (char *)tcp;
		if (cut_data) len = (tcp->th_off << 2);
		memcpy(tcpo, tcp, len);
		ipo->tot_len = htons(len + sizeof(*ip));

		tcpo->th_dport = upp->s_port;
		tcpo->th_sport = upp->d_port;
		tcpo->th_sum = 0;

		tcp_checksum(&tcpo->th_sum, 0, &ipo->saddr, &ipo->daddr, tcpo, len);
		ip_checksum(&ipo->check, ipo, sizeof(*ipo));
		return len + sizeof(*ipo);
	}

	return length;
}

