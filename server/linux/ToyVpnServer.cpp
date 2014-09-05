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

static unsigned char DNS_PADDING[] = {
	0x20, 0x88, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x77, 0x00, 0x00,
	0x01, 0x00, 0x01
};

#define LEN_PADDING sizeof(DNS_PADDING)

static int get_tunnel(char *port)
{
#if 0
	// We use an IPv6 socket to cover both IPv4 and IPv6.
	int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
	int flag = 1;
	setsockopt(tunnel, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	flag = 0;
	setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

	// Accept packets received on any local address.
	sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(atoi(port));
#endif

	// We use an IPv6 socket to cover both IPv4 and IPv6.
	int tunnel = socket(AF_INET, SOCK_DGRAM, 0);

	// Accept packets received on any local address.
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));

	fprintf(stderr, "port %d\n", atoi(port));
	// Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
	while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
		if (errno != EADDRINUSE) {
			return -1;
		}
		usleep(100000);
	}

	return tunnel;

#if 0
	// Receive packets till the secret matches.
	char packet[1024];
	socklen_t addrlen;
	do {
		addrlen = sizeof(addr);
		int n = recvfrom(tunnel, packet, sizeof(packet), 0,
				(sockaddr *)&addr, &addrlen);
		if (n <= 0) {
			fprintf(stderr, "connected packet length %d\n", n);
			return -1;
		}
		packet[n] = 0;
		fprintf(stderr, "connected packet length %d\n", n);
	} while (packet[LEN_PADDING] != 0 || strcmp(secret, &packet[LEN_PADDING + 1]));

	// Connect to the client as we only handle one client at a time.
	connect(tunnel, (sockaddr *)&addr, addrlen);
	return tunnel;
#endif
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

//-----------------------------------------------------------------------------

struct client_info {
	int flags;
	char cookies[32];

	time_t lastup;
	in_addr cltip;
	struct sockaddr target;
	unsigned total_in, total_out;
};

struct ipv4_info {
	unsigned noused1;
	unsigned noused2;
	unsigned noused3;
	unsigned source;
	unsigned target;
};

static int is_same_network(const unsigned char *data, size_t len)
{
	unsigned match0;
	unsigned int source, target;
	struct ipv4_info *iphdr = (struct ipv4_info *)data;

	source = htonl(iphdr->source);
	target = htonl(iphdr->target);

	match0 = (source ^ target) & 0xFFFFFF00;
	if ((target & 0xFF) == 1) return 0;
	return (match0 == 0);
}

static int _ll_argc = 0;
static char *_ll_argv[100];
static char _hi_secret[100];

static struct client_info _ll_client_info[256] = {0};

static int handshake_packet(int tunnel, const void *data, size_t len, struct sockaddr *from, socklen_t fromlen)
{
	int count;
	const char *check;
	const char *cookies;
	const char *handinfo;

	struct msghdr msg0;
	struct iovec  iovecs[10];

	char parameters[1024];

	handinfo = (const char *)data;

	if (len <= 0 || handinfo[0] != 0) {
		return 0;
	}

	if (strcmp(_hi_secret, handinfo + 1)) {
		return 0;
	}

	cookies = "";
	check = handinfo + 2 + strlen(_hi_secret);
	if ((int)(check - handinfo) < len && check[0] != 0) {
		fprintf(stderr, "rehandshake cookie: %s\n", check);
		cookies = check;
	}

	int cookie0 = 0;
	struct client_info *cltinfo;
	struct client_info *btrinfo;
	struct client_info *badinfo;

	for (int i = 2; i < 255; i++) {
		cltinfo = &_ll_client_info[i];
		if (0 == strcmp(cltinfo->cookies, cookies)) {
			cookie0 = (*cookies != 0);
			btrinfo = cltinfo;
			break;
		}

		if (memcmp(&cltinfo->target, from, fromlen) == 0) {
			btrinfo = cltinfo;
			cookie0 = 1;
			break;
		}

		if (cltinfo->flags == 0) {
			btrinfo = cltinfo;
		} else if (cltinfo->lastup + 100 < time(NULL)) {
			badinfo = cltinfo;
		}
	}

	if (btrinfo == NULL) {
		btrinfo = badinfo;
		cookie0 = 0;
	}

	if (btrinfo == NULL) {
		fprintf(stderr, "there no idle client, could not allocate!\n");
		return 0;
	}

	if (cookie0 == 0) {
		char ipv4[32];
		int part1 = random();
		int part2 = (int)(long)btrinfo;
		sprintf(btrinfo->cookies, "%08x.%08x", part1, part2);

		sprintf(ipv4, "10.2.0.%d", (btrinfo - _ll_client_info) & 0xFF);
		btrinfo->cltip.s_addr = inet_addr(ipv4);
	} else {
		fprintf(stderr, "rehandshake success: %s\n", inet_ntoa(btrinfo->cltip));
	}

	msg0.msg_flags = 0;
	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;

	iovecs[0].iov_len = LEN_PADDING;
	iovecs[0].iov_base = DNS_PADDING;
	iovecs[1].iov_len = sizeof(parameters);
	iovecs[1].iov_base = parameters;

	msg0.msg_name = (void *)from;
	msg0.msg_namelen = fromlen;
	msg0.msg_iov  = iovecs;
	msg0.msg_iovlen = 2;

	count = _ll_argc;
	char _vv_a[] = "-a";
	char _vv_c[] = "-c";
	char _vv_prefix[] = "24";

	_ll_argv[count++] = _vv_a;
	_ll_argv[count++] = inet_ntoa(btrinfo->cltip);
	_ll_argv[count++] = _vv_prefix;
	_ll_argv[count++] = _vv_c;
	_ll_argv[count++] = btrinfo->cookies;

	btrinfo->flags = 1;
	btrinfo->lastup = time(NULL);
	memcpy(&btrinfo->target, from, fromlen);

	iovecs[1].iov_len = build_parameters(parameters, sizeof(parameters), count, _ll_argv);
	fprintf(stderr, "build parm %s\n", parameters + 1);
	count = sendmsg(tunnel, &msg0, MSG_NOSIGNAL);

	count = sendmsg(tunnel, &msg0, MSG_NOSIGNAL);

	return 0;
}

static int dispatch_packet(int tunnel, const void *data, size_t len, struct sockaddr *from, socklen_t fromlen)
{
	struct msghdr msg0;
	struct iovec  iovecs[10];

	iovecs[0].iov_len = LEN_PADDING;
	iovecs[0].iov_base = DNS_PADDING;

	msg0.msg_flags = 0;
	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;

	int index, count;
	unsigned int source, target;
	struct ipv4_info *iphdr = (struct ipv4_info *)data;
	struct client_info *cltinfo = NULL;

	source = htonl(iphdr->source);
	target = htonl(iphdr->target);

	index = (target & 0xFF);
	if (index < 2 || index == 255) {
		fprintf(stderr, "index is invalid: %d\n", index);
		return 0;
	}

	cltinfo = &_ll_client_info[index];

	if (from != NULL && fromlen >= sizeof(*from)) {
		int chk_index = (source & 0xFF);
		struct client_info *srcinfo = &_ll_client_info[chk_index];

		if (memcmp(from, &srcinfo->target, fromlen)) {
			char reject[] = ".#REJECT";

			msg0.msg_name = (void *)from;
			msg0.msg_namelen = fromlen;
			msg0.msg_iov  = iovecs;
			msg0.msg_iovlen = 2;

			reject[0] = 0;
			iovecs[1].iov_len = sizeof(reject);
			iovecs[1].iov_base = reject;

			count = sendmsg(tunnel, &msg0, MSG_NOSIGNAL);
			return 0;
		}

		srcinfo->lastup = time(NULL);
	}

	msg0.msg_name = (void *)&cltinfo->target;
	msg0.msg_namelen = sizeof(cltinfo->target);
	msg0.msg_iov  = iovecs;
	msg0.msg_iovlen = 2;

	iovecs[1].iov_len = len;
	iovecs[1].iov_base = (void *)data;

	count = sendmsg(tunnel, &msg0, MSG_NOSIGNAL);
	if (count == -1) {
		struct sockaddr_in si, sd;
		memcpy(&si, &cltinfo->target, sizeof(si));
		fprintf(stderr, "invalid %d %s %d\n", count, strerror(errno), si.sin_family);
		fprintf(stderr, "target: %s:%d\n", inet_ntoa(si.sin_addr), htons(si.sin_port));

		si.sin_addr.s_addr = iphdr->target;
		fprintf(stderr, "isource: %s %d\n", inet_ntoa(si.sin_addr), index);

		si.sin_addr.s_addr = iphdr->source;
		fprintf(stderr, "ifrom: %s %d\n", inet_ntoa(si.sin_addr), index);
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		printf("Usage: %s <tunN> <port> <secret> options...\n"
				"\n"
				"Options:\n"
				"  -m <MTU> for the maximum transmission unit\n"
				"  -a <address/prefix-length> for the private address\n"
				"  -r <address/prefix-length> for the forwarding route\n"
				"  -d <address> for the domain name server\n"
				"  -s <domain> for the search domain\n"
				"\n"
				"Note that TUN interface needs to be configured properly\n"
				"BEFORE running this program. For more information, please\n"
				"read the comments in the source code.\n\n", argv[0]);
		exit(1);
	}

	strcpy(_hi_secret, argv[3]);
	memcpy(_ll_argv, argv, argc * sizeof(argv[0]));
	_ll_argc = argc;

#if 0
	// Parse the arguments and set the parameters.
	char parameters[1024];
	build_parameters(parameters, sizeof(parameters), argc, argv);
#endif

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
		tunnel = get_tunnel(argv[2]);

		maxfd = (tunnel > interface? tunnel: interface);
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
							tunnel_prepare = 1;
							if (length > LEN_PADDING + (int)sizeof(struct ipv4_info) && packet[LEN_PADDING]) {
								int len = length - LEN_PADDING;
								const unsigned char *adj = packet + LEN_PADDING;

								if (is_same_network(adj, len)) {
									/* route packet to other device. */
									dispatch_packet(tunnel, adj, len, &from, fromlen);
								} else {
									/* dispatch to tun device. */
									write(interface, adj, len);
								}

								lastup = time(NULL);
								dirty = 1;
							} else if (length > LEN_PADDING) {
								int len = length - LEN_PADDING;
								const unsigned char *adj = packet + LEN_PADDING;
								fprintf(stderr, "recvfrom %d %d %d\n", length, fromlen, from.sa_family);
								packet[length] = 0;
								handshake_packet(tunnel, adj, len, &from, fromlen);
								lastup = time(NULL);
								dirty = 1;
							}
						}
					}

					if (interface_prepare) {
						length = read(interface, packet, sizeof(packet));

						interface_prepare = 0;
						if (length > (int)sizeof(struct ipv4_info)) {
							interface_prepare = 1;
							dispatch_packet(tunnel, packet, length, NULL, 0);
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

#if 0
	while ((tunnel = get_tunnel(argv[2], argv[3])) != -1) {
		printf("%s: Here comes a new tunnel\n", argv[1]);

		// On UN*X, there are many ways to deal with multiple file
		// descriptors, such as poll(2), select(2), epoll(7) on Linux,
		// kqueue(2) on FreeBSD, pthread(3), or even fork(2). Here we
		// mimic everything from the client, so their source code can
		// be easily compared side by side.

		// Put the tunnel into non-blocking mode.
		fcntl(tunnel, F_SETFL, O_NONBLOCK);

		// Allocate the buffer for a single packet.
		char packet[32767];

		memcpy(packet, DNS_PADDING, LEN_PADDING);
		memcpy(packet + LEN_PADDING, parameters, sizeof(parameters));
		// Send the parameters several times in case of packet loss.
		for (int i = 0; i < 3; ++i) {
			send(tunnel, packet, sizeof(parameters) + LEN_PADDING, MSG_NOSIGNAL);
		}
		fprintf(stderr, "Here comes a new tunnel send config\n");


		// We use a timer to determine the status of the tunnel. It
		// works on both sides. A positive value means sending, and
		// any other means receiving. We start with receiving.
		int timer = 0;

		// We keep forwarding packets till something goes wrong.
		while (true) {
			// Assume that we did not make any progress in this iteration.
			bool idle = true;

			// Read the outgoing packet from the input stream.
			int length = read(interface, packet + LEN_PADDING, sizeof(packet) - LEN_PADDING);
			if (length > 0) {
				// Write the outgoing packet to the tunnel.
				memcpy(packet, DNS_PADDING, LEN_PADDING);
				send(tunnel, packet, length + LEN_PADDING, MSG_NOSIGNAL);

				// There might be more outgoing packets.
				idle = false;

				// If we were receiving, switch to sending.
				if (timer < 1) {
					timer = 1;
				}
			}

			// Read the incoming packet from the tunnel.
			length = recv(tunnel, packet, sizeof(packet), 0);
			if (length == 0) {
				break;
			}

			if (length > (int)LEN_PADDING) {
				// Ignore control messages, which start with zero.
				if (packet[LEN_PADDING] != 0) {
					// Write the incoming packet to the output stream.
					write(interface, packet + LEN_PADDING, length - LEN_PADDING);
				}

				// There might be more incoming packets.
				idle = false;

				// If we were sending, switch to receiving.
				if (timer > 0) {
					timer = 0;
				}
			}

			// If we are idle or waiting for the network, sleep for a
			// fraction of time to avoid busy looping.
			if (idle) {
				usleep(100000);

				// Increase the timer. This is inaccurate but good enough,
				// since everything is operated in non-blocking mode.
				timer += (timer > 0) ? 100 : -100;

				// We are receiving for a long time but not sending.
				// Can you figure out why we use a different value? :)
				if (timer < -16000) {
					// Send empty control messages.
					packet[LEN_PADDING] = 0;
					memcpy(packet, DNS_PADDING, LEN_PADDING);
					for (int i = 0; i < 3; ++i) {
						send(tunnel, packet, 1 + LEN_PADDING, MSG_NOSIGNAL);
					}

					// Switch to sending.
					timer = 1;
				}

				// We are sending for a long time but not receiving.
				if (timer > 20000) {
					break;
				}
			}
		}
		printf("%s: The tunnel is broken\n", argv[1]);
		close(tunnel);
	}
	perror("Cannot create tunnels");
	exit(1);
#endif

	return 0;
}
