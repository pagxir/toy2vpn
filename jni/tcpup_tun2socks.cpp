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
	int interface = open("/dev/net/tun", O_RDWR);

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

void run_config_script(const char *ifname, const char *script)
{
	char setup_cmd[8192];
	sprintf(setup_cmd, "%s %s", script, ifname);
	system(setup_cmd);
	return;
}

static void usage(const char *prog_name)
{
    fprintf(stderr, "%s [options] <server>!\n", prog_name);
    fprintf(stderr, "\t-h print this help!\n");
    fprintf(stderr, "\t-t <tun-device> use this as tun device name, default socks0!\n");
    fprintf(stderr, "\t-s <config-script> the path to config this interface when tun is up, default ./tun2socks_ifup.socks0!\n");
    fprintf(stderr, "\tall @address should use this format <host:port> OR <port>\n");
    fprintf(stderr, "\n");

    return;
}

int main(int argc, char *argv[])
{
	int count = 0;
	int interface = 0;
	unsigned relay_ip = 0;
	unsigned relay_mask = 0;
	const char *tun = "socks0";
	const char *script = "./tun2socks_ifup.socks0";
    struct sockaddr_in relay = {0};

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
        } else {
            parse_sockaddr_in(&relay, argv[i]);
            continue;
        }
    }

	setuid(0);
	interface = get_interface(tun);
	run_config_script(tun, script);
	relay_ip = (relay.sin_addr.s_addr);
	relay_mask = htonl(0xffff);

	for (;;) {
			int ln1, xdat;
			u_char buf[1500], packet[1500];

			int num = read(interface, packet, sizeof(packet));
			if (num <= 0) {
					perror("interface read");
					for (int i = 0; i < 10; i++) { sleep(1); fprintf(stderr, "."); }
					break;
			}

			ln1 = translate_ip2ip(buf, sizeof(buf), packet, num, relay_ip, relay_mask, relay.sin_port);
			if (ln1 > 0) {
					write(interface, buf, ln1);
			}
	}

	return 0;
}

