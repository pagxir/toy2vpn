/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <assert.h>

#include "pingle.h"

#ifdef __linux__

// There are several ways to play with this program. Here we just give an
// example for the simplest scenario. Let us say that a Linux box has a
// public IPv4 address on eth0. Please try the following steps and adjust
// the parameters when necessary.
//
// # Enable IP forwarding
// echo 1 > /proc/sys/net/ipv4/ip_forward
//
// # Pick a range of private addresses and perform NAT over eth0.
// iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
//
// # Create a TUN interface.
// ip tuntap add dev tun0 mode tun
//
// # Set the addresses and bring up the interface.
// ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
//
// # Create a server on port 8000 with shared secret "test".
// ./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
//
// This program only handles a session at a time. To allow multiple sessions,
// multiple servers can be created on the same port, but each of them requires
// its own TUN interface. A short shell script will be sufficient. Since this
// program is designed for demonstration purpose, it performs neither strong
// authentication nor encryption. DO NOT USE IT IN PRODUCTION!

#include <net/if.h>
#include <linux/if_tun.h>

static int get_interface(char *name)
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

#else

#error Sorry, you have to implement this part by yourself.

#endif

struct icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq;
};

struct tracker_header {
    uint32_t id_low;
    uint32_t id_high;
};

//-----------------------------------------------------------------------------

struct ipv4_header {
    unsigned noused1;
    unsigned noused2;
    unsigned noused3;
    unsigned source;
    unsigned target;
};

static int _is_dns_mode = 0;
static sockaddr _sa_router;

static unsigned char TUNNEL_PADDIND_ICMP[16]; // ICMP + TRACK
#define LEN_PADDING_ICMP sizeof(TUNNEL_PADDIND_ICMP)

static unsigned char TUNNEL_PADDIND_DNS[] = {
    0x20, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x77, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00 /* the last 8 byte is use for id_low id_high */
};
#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

static unsigned int LEN_PADDING = LEN_PADDING_ICMP;
static unsigned char *TUNNEL_PADDIND = TUNNEL_PADDIND_ICMP;

int pingle_set_dnsmode(int on)
{
	if (on == 0) {
		_is_dns_mode = 0;
		LEN_PADDING = LEN_PADDING_ICMP;
		TUNNEL_PADDIND = TUNNEL_PADDIND_ICMP;
		return 0;
	}

	_is_dns_mode = 1;
	LEN_PADDING = LEN_PADDING_DNS;
	TUNNEL_PADDIND = TUNNEL_PADDIND_DNS;
	return 0;
}

static int vpn_output(int tunnel, const void *data, size_t len);

static int get_tunnel(char *port, char *server)
{
    int count;
	int tunnel = -1;
    sockaddr_in addr;

    // We use an IPv6 socket to cover both IPv4 and IPv6.
	if (_is_dns_mode == 0) {
		tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	} else {
		tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
    assert(tunnel != -1);

    // Accept packets received on any local address.
    fprintf(stderr, "server %s\n", server);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(atoi(port));
    addr.sin_addr.s_addr = inet_addr(server);
    memcpy(&_sa_router, &addr, sizeof(addr));

    count = vpn_output(tunnel, NULL, 0);
    fprintf(stderr, "count %d\n", count);

    return tunnel;
}

static int build_parameters(char *parameters, int size, int argc, char **argv)
{
    // Well, for simplicity, we just concatenate them (almost) blindly.
    int offset = 0;

    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        // If it looks like an option, prepend a space instead of a comma.
        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        // This is just a demo app, really.
        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        // Append the delimiter and the parameter.
        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    // Fill the rest of the space with spaces.
    memset(&parameters[offset], ' ', size - offset);

    // Control messages always start with zero.
    parameters[0] = 0;
    parameters[offset++] = ' ';
    parameters[offset++] = 0;
    return offset;
}

static int _ll_argc = 0;
static char *_ll_argv[100];
static char _hi_secret[100]= "";
static char _hi_cookies[100]= "dd";
static char _hi_rejected[100]= "dd";

static uint32_t _id_low = 0;
static uint32_t _id_high = 0;

static int vpn_output(int tunnel, const void *data, size_t len)
{
    int count;
    struct msghdr msg0;
    struct iovec  iovecs[2];
    struct sockaddr_in si0;
    struct icmp_header *icmp1;
    struct tracker_header *tracker1;

    msg0.msg_flags = 0;
    msg0.msg_control = NULL;
    msg0.msg_controllen = 0;

    msg0.msg_name = (void *)&_sa_router;
    msg0.msg_namelen = sizeof(_sa_router);

    iovecs[0].iov_len = LEN_PADDING;
    iovecs[0].iov_base = TUNNEL_PADDIND;

    iovecs[1].iov_len = len;
    iovecs[1].iov_base = (void *)data;

    msg0.msg_iov  = iovecs;
    msg0.msg_iovlen = 2;

    icmp1 = (struct icmp_header *)&TUNNEL_PADDIND[0];
    tracker1 = (struct tracker_header *)&TUNNEL_PADDIND[LEN_PADDING];
    tracker1--;

	if (_is_dns_mode == 0) {
		icmp1->type = 0x8;
		icmp1->code = 0x0;
		icmp1->checksum = 0;
		icmp1->id       = 0;
		icmp1->seq      = 0;
	}
    tracker1->id_low = _id_low;
    tracker1->id_high = _id_high;

    count = sendmsg(tunnel, &msg0, MSG_NOSIGNAL);

    if (count == -1) {
        memcpy(&si0, &_sa_router, sizeof(si0));
        fprintf(stderr, "invalid %d %s %d\n", count, strerror(errno), si0.sin_family);
        fprintf(stderr, "target: %s:%d\n", inet_ntoa(si0.sin_addr), htons(si0.sin_port));
    }

    return 0;
}

static int handshake_packet(int tunnel, const void *data, size_t len)
{
	int count;
	char *pkt_ptr;
	char pkt_msg[1200];

	if (len > 0 && data != NULL) {
		pkt_ptr = (char *)data;
		pkt_ptr++;

		if (*pkt_ptr != '#') {
			fprintf(stderr, "from %s\n", pkt_ptr);
			while (pkt_ptr != NULL && *pkt_ptr && *pkt_ptr != ' ') {
				switch (*pkt_ptr) {
					case '@':
						sscanf(pkt_ptr + 2, "%s", _hi_rejected);
						fprintf(stderr, "rejected: %s\n", _hi_rejected);

						sscanf(_hi_rejected, "%x", &_id_high);
						_id_low = getpid();
						break;

					case 'c':
						sscanf(pkt_ptr + 2, "%s", _hi_cookies);
						fprintf(stderr, "cookies: %s\n", _hi_cookies);
						break;

					case 'm':
						break;

					case 'd':
						break;

					case 'a':
						break;

					case 'r':
						break;

					default:
						fprintf(stderr, "%c\n", *pkt_ptr);
						break;
				}

				pkt_ptr = strchr(pkt_ptr, ' ');
				if (pkt_ptr != NULL) pkt_ptr++;
			}

			return 0;
		} else {
			int rejcode;
			sscanf(pkt_ptr, "#REJECT %x", &rejcode);
			if (rejcode != _id_high) return 0;
		}
	}

	pkt_ptr  = pkt_msg;
	count    = sprintf(pkt_ptr, ".%s%c%s", _hi_secret, 0, _hi_cookies);
	fprintf(stderr, "handshake: %s / %s %d\n", pkt_msg, pkt_msg + strlen(pkt_msg) + 1, count);
	pkt_msg[0] = 0;

	uint32_t save = _id_high;
	_id_high = 0;
	vpn_output(tunnel, pkt_msg, count);
	vpn_output(tunnel, pkt_msg, count);
	_id_high = save;
	return 0;
}

int main(int argc, char **argv)
{
    struct icmp_header *icmp_header;

    if (argc < 5) {
        printf("Usage: %s <tunN> <port> <secret> server\n"
                "\n"
                "Note that TUN interface needs to be configured properly\n"
                "BEFORE running this program. For more information, please\n"
                "read the comments in the source code.\n\n", argv[0]);
        exit(1);
    }

    _ll_argc = argc;
    strcpy(_hi_secret, argv[3]);
    memcpy(_ll_argv, argv, argc * sizeof(argv[0]));

    // Wait for a tunnel.
    int tunnel;
    int dirty = 0;
    time_t lastup = time(NULL);

    // Get TUN interface.
    int interface = get_interface(argv[1]);

    do {
        int maxfd;
        int count;
        fd_set readfds;
        struct timeval timeout;

        dirty = 0;
        lastup = time(NULL);
        tunnel = get_tunnel(argv[2], argv[4]);

        maxfd = (tunnel > interface? tunnel: interface);
        fcntl(tunnel, F_SETFL, O_NONBLOCK);
        handshake_packet(tunnel, NULL, 0);

        for (; ; ) {
            FD_ZERO(&readfds);
            FD_SET(tunnel, &readfds);
            FD_SET(interface, &readfds);

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;
            count = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

            if (count == -1) {
                fprintf(stderr, "select error %s\n", strerror(errno));
                exit(-1);
            }

            if (count > 0) {
                int length;
                int tunnel_prepare;
                int interface_prepare;

                struct sockaddr from;
                unsigned char packet[2048];
                socklen_t fromlen = sizeof(from);

                tunnel_prepare = FD_ISSET(tunnel, &readfds);
                interface_prepare = FD_ISSET(interface, &readfds);

                do {
                    if (tunnel_prepare) {
                        length = recvfrom(tunnel, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

                        tunnel_prepare = 0;
                        if (length > 0) {
                            struct tracker_header *trak;
                            tunnel_prepare = 1;

                            trak = (struct tracker_header *)&packet[LEN_PADDING];
                            trak--;
                            if (length > LEN_PADDING && packet[LEN_PADDING] == 0) {
                                int len = length - LEN_PADDING;
                                const unsigned char *adj = packet + LEN_PADDING;
                                fprintf(stderr, "recvfrom %d %d %d\n", length, fromlen, from.sa_family);
                                packet[length] = 0;
                                handshake_packet(tunnel, adj, len);
                                lastup = time(NULL);
                                dirty = 1;
                            } else if (length > LEN_PADDING + (int)sizeof(struct ipv4_header)) {
                                int len = length - LEN_PADDING;
                                const unsigned char *adj = packet + LEN_PADDING;

                                /* dispatch to tun device. */
                                write(interface, adj, len);

                                lastup = time(NULL);
                                dirty = 1;
                            }
                        }
                    }

                    if (interface_prepare) {
                        length = read(interface, packet, sizeof(packet));

                        interface_prepare = 0;
                        if (length > (int)sizeof(struct ipv4_header)) {
                            vpn_output(tunnel, packet, length);
                            interface_prepare = 1;
                        }
                    }

                } while (tunnel_prepare || interface_prepare);

                continue;
            }

            if (dirty && lastup + 60 < time(NULL)) {
                fprintf(stderr, "idle for long time, try to recreate interface\n");
                break;
            }
        }

        close(tunnel);

    } while (true);

    close(interface);

    return 0;
}

int pingle_get_configure(int tunnel, char *buf, size_t size)
{
	int count;
	int length;
	int tunnel_prepare;

	fd_set readfds;
	struct timeval timeout;

	struct sockaddr from;
	unsigned char packet[2048];
	socklen_t fromlen = sizeof(from);

	for ( ; ; ) {
		FD_ZERO(&readfds);
		FD_SET(tunnel, &readfds);

		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		count = select(tunnel + 1, &readfds, NULL, NULL, &timeout);

		if (count == -1) {
			fprintf(stderr, "select error %s\n", strerror(errno));
			return 0;
		}

		if (count == 0) {
			fprintf(stderr, "select timeout %s\n", strerror(errno));
			return 0;
		}

		tunnel_prepare = FD_ISSET(tunnel, &readfds);
		while (tunnel_prepare) {
			struct tracker_header *trak;
			length = recvfrom(tunnel, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

			tunnel_prepare = 0;
			if (length > 0) {
				tunnel_prepare = 1;
				trak = (struct tracker_header *)&packet[LEN_PADDING];
				trak--;
				if (length > LEN_PADDING && packet[LEN_PADDING] == 0 && packet[LEN_PADDING + 1]  != '#') {
					int len = length - LEN_PADDING;
					const unsigned char *adj = packet + LEN_PADDING;
					packet[length] = 0;
					if (len > size) len = size;
					memcpy(buf, adj + 1, len - 1);
					return strlen(buf);
				}
			}
		}
	}

	return 0;
}

int pingle_set_cookies(const char *cookies)
{
	strncpy(_hi_cookies, cookies, sizeof(_hi_cookies));
	return 0;
}

int pingle_set_session(const char *session)
{
	strncpy(_hi_rejected, session, sizeof(_hi_rejected));
	sscanf(_hi_rejected, "%x", &_id_high);
	return 0;
}

int pingle_set_secret(const char *secret)
{
	strncpy(_hi_secret, secret, sizeof(_hi_secret));
	return 0;
}

int pingle_do_loop(int tunnel, int interface)
{
	int maxfd;
	int count;
	fd_set readfds;
	struct timeval timeout;
	time_t lastup = time(NULL);

	maxfd = (tunnel > interface? tunnel: interface);
	fcntl(tunnel, F_SETFL, O_NONBLOCK);
	fcntl(interface, F_SETFL, O_NONBLOCK);

	for (; ; ) {
		int length;
		int tunnel_prepare;
		int interface_prepare;

		struct sockaddr from;
		struct tracker_header *trak;
		unsigned char packet[2048];
		socklen_t fromlen = sizeof(from);

		FD_ZERO(&readfds);
		FD_SET(tunnel, &readfds);
		FD_SET(interface, &readfds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		count = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

		if (count == -1) {
			fprintf(stderr, "select error %s\n", strerror(errno));
			return 0;
		}

		if (count == 0) {
			fprintf(stderr, "timeout\n");
			continue;
		}

		tunnel_prepare = FD_ISSET(tunnel, &readfds);
		interface_prepare = FD_ISSET(interface, &readfds);

		do {
			if (tunnel_prepare) {
				length = recvfrom(tunnel, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

				tunnel_prepare = 0;
				if (length > 0) {
					tunnel_prepare = 1;

					trak = (struct tracker_header *)&packet[LEN_PADDING];
					if (length > LEN_PADDING && packet[LEN_PADDING] == 0) {
						fprintf(stderr, "recvfrom %d %d %d\n", length, fromlen, from.sa_family);
						if (packet[LEN_PADDING + 1] == '#') return 0;
						lastup = time(NULL);
					} else if (length > LEN_PADDING + (int)sizeof(struct ipv4_header)) {
						int len = length - LEN_PADDING;
						const unsigned char *adj = packet + LEN_PADDING;

						/* dispatch to tun device. */
						write(interface, adj, len);

						lastup = time(NULL);
					}
				}
			}

			if (interface_prepare) {
				length = read(interface, packet, sizeof(packet));

				interface_prepare = 0;
				if (length > (int)sizeof(struct ipv4_header)) {
					vpn_output(tunnel, packet, length);
					interface_prepare = 1;
				}
			}

		} while (tunnel_prepare || interface_prepare);
	}

    return 0;
}

int pingle_do_handshake(int tunnel)
{
    int count;
    char *pkt_ptr;
    char pkt_msg[1200];

    pkt_ptr  = pkt_msg;
    count    = sprintf(pkt_ptr, ".%s%c%s", _hi_secret, 0, _hi_cookies);
    fprintf(stderr, "handshake: %s / %s %d\n", pkt_msg, pkt_msg + strlen(pkt_msg) + 1, count);
    pkt_msg[0] = 0;

    uint32_t save = _id_high;
    _id_high = 0;
	_id_low = getpid();
    vpn_output(tunnel, pkt_msg, count);
    vpn_output(tunnel, pkt_msg, count);
    _id_high = save;

	return 0;
}

int pingle_open(void)
{
    int tunnel;

    // We use an IPv6 socket to cover both IPv4 and IPv6.
	if (_is_dns_mode == 0) {
		tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	} else {
		tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

	return tunnel;
}

int pingle_set_server(const void *server, size_t len)
{
    int count;
    sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(53);
    memcpy(&addr.sin_addr, server, 4);

    memcpy(&_sa_router, &addr, sizeof(addr));
	return 0;
}
