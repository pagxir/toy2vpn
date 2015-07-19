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

void run_config_script(const char *ifname, const char *script)
{
	char setup_cmd[8192];
	sprintf(setup_cmd, "%s %s", script, ifname);
	system(setup_cmd);
	return;
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

struct ipv4_header {
	unsigned noused1;
	unsigned noused2;
	unsigned noused3;
	unsigned source;
	unsigned target;
};

static int _report_len = 0;
static int _is_dns_mode = 0;

static sockaddr _sa_router;
static unsigned char _report_name[8];

static unsigned char TUNNEL_PADDIND_ICMP[16] = {
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec
}; // ICMP + TRACK

#define LEN_PADDING_ICMP sizeof(TUNNEL_PADDIND_ICMP)

static unsigned char TUNNEL_PADDIND_DNS[] = {
	0x20, 0x88, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x77, 0x77, 0x77,
	0x77, 0x00, 0x00, 0x01, 0x00, 0x01
};
#define LEN_PADDING_DNS sizeof(TUNNEL_PADDIND_DNS)

static unsigned int LEN_PADDING = LEN_PADDING_ICMP;
static unsigned char *TUNNEL_PADDIND = TUNNEL_PADDIND_ICMP;

int parse_sockaddr_in(struct sockaddr_in *info, const char *address)
{
    const char *last;

#define FLAG_HAVE_DOT    1
#define FLAG_HAVE_ALPHA  2
#define FLAG_HAVE_NUMBER 4
#define FLAG_HAVE_SPLIT  8

    int flags = 0;
    char host[128] = {};

    info->sin_family = AF_INET;
    info->sin_port   = htons(0);
    info->sin_addr.s_addr = htonl(0);

    for (last = address; *last; last++) {
        if (isdigit(*last)) flags |= FLAG_HAVE_NUMBER;
        else if (*last == ':') flags |= FLAG_HAVE_SPLIT;
        else if (*last == '.') flags |= FLAG_HAVE_DOT;
        else if (isalpha(*last)) flags |= FLAG_HAVE_ALPHA;
        else { fprintf(stderr, "get target address failure!\n"); return -1;}
    }


    if (flags == FLAG_HAVE_NUMBER) {
        info->sin_port = htons(atoi(address));
        return 0;
    }

    if (flags == (FLAG_HAVE_NUMBER| FLAG_HAVE_DOT)) {
        info->sin_addr.s_addr = inet_addr(address);
        return 0;
    }

    struct hostent *host0 = NULL;
    if ((flags & ~FLAG_HAVE_NUMBER) == (FLAG_HAVE_ALPHA | FLAG_HAVE_DOT)) {
        host0 = gethostbyname(address);
        if (host0 != NULL)
            memcpy(&info->sin_addr, host0->h_addr, 4);
        return 0;
    }

    if (flags & FLAG_HAVE_SPLIT) {
        const char *split = strchr(address, ':');
        info->sin_port = htons(atoi(split + 1));

        if (strlen(address) < sizeof(host)) {
            strncpy(host, address, sizeof(host));
            host[split - address] = 0;

            if (flags & FLAG_HAVE_ALPHA) {
                host0 = gethostbyname(host);
                if (host0 != NULL)
                    memcpy(&info->sin_addr, host0->h_addr, 4);
                return 0;
            }

            info->sin_addr.s_addr = inet_addr(host);
        }
    }

    return 0;
}

static int get_tunnel(struct sockaddr_in *addrp)
{
    int error;
    int bufsiz = 512 * 1024;

	// We use an IPv6 socket to cover both IPv4 and IPv6.
#ifndef USE_DNS_MODE
	int tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
#else
	int tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
	assert(tunnel != -1);

#if 0
    error = setsockopt(tunnel, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
    error = setsockopt(tunnel, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));
#endif

    error = bind(tunnel, (struct sockaddr *)addrp, sizeof(*addrp));
    fprintf(stderr, "bind to %s\n", inet_ntoa(addrp->sin_addr));
    assert(error == 0);

	return tunnel;
}

static int vpn_output(int tunnel, const void *data, size_t len, int xdat)
{
	int count;
	struct msghdr msg0;
	struct iovec  iovecs[2];
	struct sockaddr_in si0;
	struct icmp_header *icmp1;

	msg0.msg_flags = 0;
	msg0.msg_control = NULL;
	msg0.msg_controllen = 0;

	msg0.msg_name = (void *)&_sa_router;
	msg0.msg_namelen = sizeof(_sa_router);

	iovecs[0].iov_len = LEN_PADDING;
	iovecs[0].iov_base = TUNNEL_PADDIND;
    memcpy(TUNNEL_PADDIND, _report_name, _report_len);

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

	if (_is_dns_mode == 0) {
		icmp1 = (struct icmp_header *)TUNNEL_PADDIND;
		icmp1->type = 0x8;
		icmp1->code = 0x0;
		icmp1->checksum = 0;
		icmp1->id       = 0x3456;
		icmp1->seq      = xdat;
	}

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

static void usage(const char *prog_name)
{
    fprintf(stderr, "%s [options] <server>!\n", prog_name);
    fprintf(stderr, "\t-h print this help!\n");
    fprintf(stderr, "\t-t <tun-device> use this as tun device name, default tun0!\n");
    fprintf(stderr, "\t-s <config-script> the path to config this interface when tun is up, default ./ifup.tun0!\n");
    fprintf(stderr, "\t-r <return-address> tell server use this address as feedback address!\n");
    fprintf(stderr, "\t-i <interface-address> interface address, local address use for outgoing/incoming packet!\n");
    fprintf(stderr, "\tall @address should use this format <host:port> OR <port>\n");
    fprintf(stderr, "\n");

    return;
}

#define DNS_MAGIC_LEN 24
static unsigned char dns_magic[DNS_MAGIC_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
};


int main(int argc, char **argv)
{
	int dirty = 0;
    int interface = 0;
	int tunnel, tunnel_udp = 0;
	time_t lastup = time(NULL);
	struct icmp_header *icmp_header;
    struct sockaddr_in report_name = {0}, bind_name = {0}, relay_name = {0};

    const char *tun = "tun0";
    const char *script = "./ifup.tun0";

    bind_name.sin_family = AF_INET;
    relay_name.sin_family = AF_INET;
    report_name.sin_family = AF_INET;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            script = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            tun = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
            parse_sockaddr_in(&report_name, argv[i + 1]);
            i++;
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            parse_sockaddr_in(&bind_name, argv[i + 1]);
            i++;
        } else {
            parse_sockaddr_in(&relay_name, argv[i]);
            continue;
        }
    }

    if (!relay_name.sin_addr.s_addr) {
        usage(argv[0]);
        return 0;
    }

	setuid(0);
	interface = get_interface(tun);
	run_config_script(tun, script);
    memcpy(&_sa_router, &relay_name, sizeof(relay_name));

	do {
		int maxfd;
		int count;
		fd_set readfds;
		struct timeval timeout;

		dirty = 0;
		lastup = time(NULL);
		tunnel = get_tunnel(&bind_name);
		tunnel_udp = get_tunnel_udp(&bind_name);

        if (report_name.sin_addr.s_addr) {
            int error;
            socklen_t v4alen;
            struct sockaddr_in v4addr;

            if (report_name.sin_port == 0) {
                v4alen = sizeof(v4addr);
                error  = getsockname(tunnel, (struct sockaddr *)&v4addr, &v4alen);
                if (error == 0) {
                    memcpy(_report_name, &report_name.sin_addr, 4);
                    memcpy(_report_name + 6, &v4addr.sin_port, 2);
                    _report_len = 8;
                }
            } else {
                memcpy(_report_name, &report_name.sin_addr, 4);
                memcpy(_report_name + 6, &report_name.sin_port, 2);
                _report_len = 8;
            }
        }

		maxfd = (tunnel > interface? tunnel: interface);
		maxfd = (tunnel_udp > maxfd? tunnel_udp: maxfd);
		fcntl(tunnel, F_SETFL, O_NONBLOCK);
		fcntl(interface, F_SETFL, O_NONBLOCK);
		fcntl(tunnel_udp, F_SETFL, O_NONBLOCK);

		for (; ; ) {
			FD_ZERO(&readfds);
			FD_SET(tunnel, &readfds);
			FD_SET(interface, &readfds);
			FD_SET(tunnel_udp, &readfds);

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
				int tunnel_udp_prepare;

				struct sockaddr from;
				unsigned char buf[2048];
				unsigned char packet[2048];
				socklen_t fromlen = sizeof(from);

				tunnel_prepare = FD_ISSET(tunnel, &readfds);
				interface_prepare = FD_ISSET(interface, &readfds);
				tunnel_udp_prepare = FD_ISSET(tunnel_udp, &readfds);

				do {
					if (tunnel_prepare) {
						length = recvfrom(tunnel, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

						tunnel_prepare = 0;
						if (length > 0) {
							tunnel_prepare = 1;

							if (length >= LEN_PADDING + (int)sizeof(struct tcpuphdr)) {
								int len = length - LEN_PADDING;
								unsigned char *adj = packet + LEN_PADDING;

								unsigned short key = 0;
								memcpy(&key, packet + 14, 2);

								static u_char plain[1500];
								packet_decrypt(key, plain, adj, len);

								int len1 = 0;
								if (length >= 12 + DNS_MAGIC_LEN && 0 == memcmp(plain, dns_magic, DNS_MAGIC_LEN)) {
									int newlen = resolved_dns_packet(buf, plain + DNS_MAGIC_LEN, len - DNS_MAGIC_LEN, (struct sockaddr_in *)&from);
									if (newlen > 12) len1 = newlen;
								} else {
									/* dispatch to tun device. */
									len1 = translate_up2ip(buf, sizeof(buf), plain, len);
								}

								if (len1 > 0) {
									//fprintf(stderr, "write to tun length: %d\n", length);
									write(interface, buf, len1);
								} else if (len1 == -1) {
									//fprintf(stderr, "write to tun length: %d\n", length);
									len1 = tcpup_reset_fill(buf, plain, len);
									vpn_output(tunnel, buf, len, 0);
								}

								lastup = time(NULL);
								dirty = 1;
							} else fprintf(stderr, "small length: %d\n", length);
						}
					}

					if (tunnel_udp_prepare) {
						length = recvfrom(tunnel_udp, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

						tunnel_udp_prepare = 0;
						if (length > 0) {
							tunnel_udp_prepare = 1;
							fprintf(stderr, "good write to tun length: %d\n", length);

							if (length >= 12) {
								length = resolved_dns_packet(buf, packet, length, (struct sockaddr_in *)&from);
								if (length > 0) {
									fprintf(stderr, "set write to tun length: %d\n", length);
									write(interface, buf, length);
								}
								lastup = time(NULL);
								dirty = 1;
							}
						}
					}

					if (interface_prepare) {
						int xdat = 0x0;
						length = read(interface, packet, sizeof(packet));

						interface_prepare = 0;

						if (length > (int)sizeof(struct ipv4_header)) {
							int newlen = fill_out_ip2udp((char *)(buf + 24), packet, length);

							if (newlen > 12) {
								memcpy(buf, dns_magic, DNS_MAGIC_LEN);
								length = newlen + DNS_MAGIC_LEN;
							} else {
								/* should be an tcp packet, so do traslate now. */
								length = translate_ip2up(buf, sizeof(buf), packet, length, &xdat);
							}

							if (length > 0) {
								// fprintf(stderr, "send out packet: %d\n", length);
								vpn_output(tunnel, buf, length, xdat);
							} else if (length == -1) {
								int len = tcp_reset_fill(buf, packet, length);
								fprintf(stderr, "send back reset packet: %d\n", len);
								write(interface, buf, len);
							}

							interface_prepare = 1;
						}
					}

				} while (tunnel_prepare || interface_prepare || tunnel_udp_prepare);

				continue;
			}

			if (dirty && lastup + 600 < time(NULL)) {
				fprintf(stderr, "idle for long time, try to recreate interface\n");
				break;
			}
		}

		close(tunnel_udp);
		close(tunnel);

	} while (true);

	close(interface);

	return 0;
}

int pingle_get_configure(int tunnel, char *buf, size_t size)
{
	static char conf[] = {"m,1280 d,114.114.114.114 a,10.2.0.15,24 a,2002:c0a8::2,100 r,::,0 rL,EXTERNAL c,2ae8944a.0805159c @,625558ec "};
	strncpy(buf, conf, size);
	return sizeof(conf) - 1;
}

int pingle_set_cookies(const char *cookies)
{
	//strncpy(_hi_cookies, cookies, sizeof(_hi_cookies));
	return 0;
}

int pingle_set_session(const char *session)
{
	//strncpy(_hi_rejected, session, sizeof(_hi_rejected));
	//sscanf(_hi_rejected, "%x", &_id_high);
	return 0;
}

int pingle_set_secret(const char *secret)
{
	//strncpy(_hi_secret, secret, sizeof(_hi_secret));
	return 0;
}

int pingle_do_loop(int tunnel, int tunnel_udp, int interface)
{
	int maxfd;
	int count;
	fd_set readfds;
	struct timeval timeout;
	time_t lastup = time(NULL);

	maxfd = (tunnel > interface? tunnel: interface);
	maxfd = (tunnel_udp > maxfd? tunnel_udp: maxfd);

	fcntl(tunnel, F_SETFL, O_NONBLOCK);
	fcntl(interface, F_SETFL, O_NONBLOCK);
	fcntl(tunnel_udp, F_SETFL, O_NONBLOCK);

	for (; ; ) {
		int length;
		int tunnel_prepare;
		int interface_prepare;
		int tunnel_udp_prepare;

		struct sockaddr from;
		unsigned char buf[2048];
		unsigned char packet[2048];
		socklen_t fromlen = sizeof(from);

		FD_ZERO(&readfds);
		FD_SET(tunnel, &readfds);
		FD_SET(interface, &readfds);
		FD_SET(tunnel_udp, &readfds);

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		count = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

		if (count == -1) {
			fprintf(stderr, "select error %s\n", strerror(errno));
			return 0;
		}

		if (count == 0) {
			fprintf(stderr, "timeout\n");
			int count = tcpup_do_keepalive(vpn_output, tunnel, 0);
#ifdef __ANDROID__
			 __android_log_print(ANDROID_LOG_INFO, "TOYVPN-JNI", "timeout %x", count);
#endif
			continue;
		}

		tunnel_prepare = FD_ISSET(tunnel, &readfds);
		interface_prepare = FD_ISSET(interface, &readfds);
		tunnel_udp_prepare = FD_ISSET(tunnel_udp, &readfds);

		do {
			if (tunnel_prepare) {
				length = recvfrom(tunnel, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

				tunnel_prepare = 0;
				if (length > 0) {
					tunnel_prepare = 1;

					if (length >= LEN_PADDING + (int)sizeof(struct tcpuphdr)) {
						int len = length - LEN_PADDING;
						unsigned char *adj = packet + LEN_PADDING;

						unsigned short key = 0;
						memcpy(&key, packet + 14, 2);

						static u_char plain[1500];
						packet_decrypt(key, plain, adj, len);

						int len1 = 0;
						if (length >= 12 + DNS_MAGIC_LEN && 0 == memcmp(plain, dns_magic, DNS_MAGIC_LEN)) {
							int newlen = resolved_dns_packet(buf, plain + DNS_MAGIC_LEN, len - DNS_MAGIC_LEN, (struct sockaddr_in *)&from);
							if (newlen > 12) len1 = newlen;
						} else {
							/* dispatch to tun device. */
							len1 = translate_up2ip(buf, sizeof(buf), plain, len);
						}

						if (len1 > 0) {
							//fprintf(stderr, "write to tun length: %d\n", length);
							write(interface, buf, len1);
						} else if (len1 == -1) {
							//fprintf(stderr, "write to tun length: %d\n", length);
							len1 = tcpup_reset_fill(buf, plain, len);
							if (vpn_output(tunnel, buf, len, 0) == -1) return 0;
						}

					}
				}
			}

			if (tunnel_udp_prepare) {
				length = recvfrom(tunnel_udp, packet, sizeof(packet), MSG_DONTWAIT, &from, &fromlen);

				tunnel_udp_prepare = 0;
				if (length > 0) {
					tunnel_udp_prepare = 1;
					fprintf(stderr, "good write to tun length: %d\n", length);

					if (length >= 12) {
						length = resolved_dns_packet(buf, packet, length, (struct sockaddr_in *)&from);
						if (length > 0) {
							fprintf(stderr, "set write to tun length: %d\n", length);
							write(interface, buf, length);
						}
						lastup = time(NULL);
					}
				}
			}

			if (interface_prepare) {
				length = read(interface, packet, sizeof(packet));

				interface_prepare = 0;
				if (length > (int)sizeof(struct ipv4_header)) {
					int xdat = 0;
					int newlen = fill_out_ip2udp((char *)(buf + 24), packet, length);

					interface_prepare = 1;
					if (newlen > 12) {
						memcpy(buf, dns_magic, DNS_MAGIC_LEN);
						length = newlen + DNS_MAGIC_LEN;
					} else {
						/* should be an tcp packet, so do traslate now. */
						length = translate_ip2up(buf, sizeof(buf), packet, length, &xdat);
					}

					if (length > 0) {
						// fprintf(stderr, "send out packet: %d\n", length);
						if (vpn_output(tunnel, buf, length, xdat) == -1) return 0;
					} else if (length == -1) {
						int len = tcp_reset_fill(buf, packet, length);
						fprintf(stderr, "send back reset packet: %d\n", len);
						write(interface, buf, len);
					}
				}
			}

		} while (tunnel_prepare || interface_prepare || tunnel_udp_prepare);

	}

    return 0;
}

int pingle_do_handshake(int tunnel)
{
	return 0;
}

int pingle_set_dnsmode(int on)
{
	if (on == 0) {
		_is_dns_mode = 0;
		TUNNEL_PADDIND = TUNNEL_PADDIND_ICMP;
		LEN_PADDING = LEN_PADDING_ICMP;
		return 0;
	}

	TUNNEL_PADDIND_DNS[2] &= ~0x80;
	TUNNEL_PADDIND_DNS[3] &= ~0x80;
	TUNNEL_PADDIND = TUNNEL_PADDIND_DNS;
	LEN_PADDING = LEN_PADDING_DNS;
	_is_dns_mode = 1;
	return 0;
}

int pingle_open(void)
{
	int tunnel;
	int bufsiz = 512 * 1024;

	// We use an IPv6 socket to cover both IPv4 and IPv6.
	if (_is_dns_mode == 0) {
		tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	} else {
		tunnel = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}

#if 0
	if (tunnel != -1) {
		setsockopt(tunnel, SOL_SOCKET, SO_SNDBUF, (char *)&bufsiz, sizeof(bufsiz));
		setsockopt(tunnel, SOL_SOCKET, SO_RCVBUF, (char *)&bufsiz, sizeof(bufsiz));
	}
#endif

	return tunnel;
}

int pingle_set_server(const void *server, int port, size_t len)
{
    int count;
    sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, server, 4);

    memcpy(&_sa_router, &addr, sizeof(addr));
	return 0;
}
