#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>

#include "pingle.h"
#include "tcpup/up.h"
#include "tcpup/ip.h"
#include "tcpup/crypt.h"
#include "tcpup/dnstrak.h"
#include "tcpup/contrak.h"

#ifdef __linux__
#include <net/if.h>
#include <linux/if_tun.h>
#endif

static unsigned char TUNNEL_PADDIND_ICMP[16] = {
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec
}; // ICMP + TRACK

//#define LEN_PADDING sizeof(TUNNEL_PADDIND_ICMP)

static unsigned char TUNNEL_PADDIND[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
	0x77, 0x00, 0x00, 0x01, 0x00, 0x01
};
#define LEN_PADDING sizeof(TUNNEL_PADDIND)

int get_tunnel(void)
{
	int error;
	int fildes;
	struct sockaddr_in zero = {0};

	zero.sin_family = AF_INET;
	zero.sin_port   = htons(4345);
	
	//fildes = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	fildes = socket(AF_INET, SOCK_DGRAM, 0);

    error  = bind(fildes, (struct sockaddr *)&zero, sizeof(zero));
    assert(error == 0);

	return fildes;
}

static int get_interface(const char *name)
{
	int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

	if (ioctl(interface, TUNSETIFF, &ifr)) {
		perror("Cannot get TUN interface");
		exit(1);
	}

	return interface;
}

static sockaddr _sa_router;
static int vpn_output(int tunnel, const void *data, size_t len, int xdat)
{
	int count;
	struct msghdr msg0;
	struct iovec  iovecs[2];
	struct sockaddr_in si0;
	//struct icmp_header *icmp1;

	msg0.msg_flags = 0;
	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;

	msg0.msg_name = (void *)&_sa_router;
	msg0.msg_namelen = sizeof(_sa_router);

	iovecs[0].iov_len = LEN_PADDING;
	iovecs[0].iov_base = TUNNEL_PADDIND;
    //memcpy(TUNNEL_PADDIND, _report_name, _report_len);

	msg0.msg_iov  = iovecs;
	msg0.msg_iovlen = 2;

#ifndef DISABLE_ENCRYPT
#define RCVPKT_MAXSIZ 1500
	unsigned short key = rand();
	unsigned char _crypt_stream[RCVPKT_MAXSIZ];

	memcpy(TUNNEL_PADDIND + 14, &key, 2);
	packet_encrypt(key, _crypt_stream, data, len);
	iovecs[1].iov_base = _crypt_stream;
	iovecs[1].iov_len  = len;

	msg0.msg_iov  = (struct iovec*)iovecs;
	msg0.msg_iovlen = 2;
#else
	iovecs[1].iov_len = len;
	iovecs[1].iov_base = (void *)data;
#endif

#if 0
	if (_is_dns_mode == 0) {
		icmp1 = (struct icmp_header *)TUNNEL_PADDIND;
		icmp1->type = 0x8;
		icmp1->code = 0x0;
		icmp1->checksum = 0;
		icmp1->id       = 0x3456;
		icmp1->seq      = xdat;
	}
#endif

	count = sendmsg(tunnel, &msg0, MSG_NOSIGNAL);

#if 0
	if (count == -1) {
		memcpy(&si0, &_sa_router, sizeof(si0));
		LOGE("invalid %d %s %d %d %d\n", count, strerror(errno), si0.sin_family, _is_dns_mode, tunnel);
		LOGE("target: %s:%d\n", inet_ntoa(si0.sin_addr), htons(si0.sin_port));
	}
#endif

	return count;
}

int main(int argc, char *argv[])
{
	int count = 0;
	int maxfd = 0;
	int tunnel = get_tunnel();
	int interface = get_interface("tun1");

	fd_set readfds;
	struct timeval timeout;

	fcntl(tunnel, F_SETFL, O_NONBLOCK);
	fcntl(interface, F_SETFL, O_NONBLOCK);
	maxfd = (tunnel < interface? interface: tunnel);

	system("ifconfig tun1 10.7.0.15/16 mtu 1420 up");
	while (true) {
		u_char packet[1500];

		FD_ZERO(&readfds);
		FD_SET(tunnel, &readfds);
		FD_SET(interface, &readfds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		count = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

		if (count == 0 || count == -1) {
			if (errno == EINTR) {
				count = 0;
			}

			if (count == 0) {
				//fprintf(stderr, "keep alive\n");
				continue;
			}

			break;
		}

		if (FD_ISSET(interface, &readfds)) {
			u_char buf[1500];
			int ln1, xdat;
			unsigned *fakeack;
			int num = read(interface, packet, sizeof(packet));
			//fprintf(stderr, "TUNNEL num %d\n", num);
			if (num > 0) {

				ln1 = translate_ip2up(buf, sizeof(buf), packet, num, &xdat, &fakeack);

			if (ln1 > 10) {
				//fprintf(stderr, "vpn_ouput ln1 %d\n", ln1);
				vpn_output(tunnel, buf, ln1, xdat);
			}
		}

		if (FD_ISSET(tunnel, &readfds)) {
			int num;
			struct sockaddr_in from;
			socklen_t fromlen = sizeof(from);

			num = recvfrom(tunnel, packet, sizeof(packet),
					MSG_DONTWAIT, (struct sockaddr *)&from, &fromlen);
			fprintf(stderr, "ICMP num %d\n", num);
			if (num > 0) {

				u_short key = 0;
				u_char buf[1500];
				static u_char plain[1500];
				int len = num - LEN_PADDING;
				u_char *adj = (u_char *)packet + LEN_PADDING;

				memcpy(&key, packet + 14, 2);
				packet_decrypt(key, plain, adj, len);

				int ln1 = translate_up2ip(buf, sizeof(buf), plain, len);
				if (ln1 > 20) {
					write(interface, buf, ln1);
					memcpy(&_sa_router, &from, fromlen);
				}
			}
		}

	}

	return 0;
}

