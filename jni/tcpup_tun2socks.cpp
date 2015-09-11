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

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <assert.h>

#include "pingle.h"
#include "tcpup/up.h"
#include "tcpup/ip.h"
#include "tcpup/dnstrak.h"
#include "tcpup/contrak.h"

#ifdef __linux__
#include <net/if.h>
#include <linux/if_tun.h>
#endif

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

int main(int argc, char *argv[])
{
	int count = 0;
	int maxfd = 0;
	int interface = get_interface("tun1");

	fd_set readfds;
	struct timeval timeout;

	maxfd = interface;
	fcntl(interface, F_SETFL, O_NONBLOCK);

	system("ifconfig tun1 10.3.0.1/16 mtu 1420");
	system("ifconfig tun1 10.3.0.1/16 up");
	system("ip -4 r a 115.239.210.27 dev tun1");
    system("ip -6 addr add 2001:c0a8:2b01::1/64 dev tun1");
    system("ip -6 route add default dev tun1 metric 256 proto static");


	while (true) {
		u_char packet[1500];

		FD_ZERO(&readfds);
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
			unsigned char *fakeack;
			int num = read(interface, packet, sizeof(packet));
			if (num > 0) {
				ln1 = translate_ip2ip(buf, sizeof(buf), packet, num);
				if (ln1 > 0) {
					write(interface, buf, ln1);
				}
			}
		}
	}

	return 0;
}

