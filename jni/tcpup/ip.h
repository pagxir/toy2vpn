#ifndef _TCPUP_IP_H_
#define _TCPUP_IP_H_

#ifndef tcp_seq
#define tcp_seq tcp_seq
typedef u_int32_t tcp_seq;
#endif

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcpiphdr
{
	u_int16_t th_sport;     /* source port */
	u_int16_t th_dport;     /* destination port */
	tcp_seq th_seq;     /* sequence number */
	tcp_seq th_ack;     /* acknowledgement number */
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t th_x2:4;       /* (unused) */
	u_int8_t th_off:4;      /* data offset */
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t th_off:4;      /* data offset */
	u_int8_t th_x2:4;       /* (unused) */
#  endif
	u_int8_t th_flags;

#ifndef TH_FIN
#  define TH_FIN    0x01
#  define TH_SYN    0x02
#  define TH_RST    0x04
#  define TH_PUSH   0x08
#  define TH_ACK    0x10
#  define TH_URG    0x20
#endif

	u_int16_t th_win;       /* window */
	u_int16_t th_sum;       /* checksum */
	u_int16_t th_urp;       /* urgent pointer */
};

struct tcpupopt;
int tcpip_dooptions(struct tcpupopt *to, u_char *cp, int cnt);
int tcpip_addoptions(struct tcpupopt *to, u_char *cp);
int tcp_checksum(void *store, struct in_addr *src, struct in_addr *dst, void *buf, size_t len);
int udp_checksum(void *store, struct in_addr *src, struct in_addr *dst, void *buf, size_t len);
int ip_checksum(void *store, void *buf, size_t len);
#endif
