#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>

#include "tcpup/ip.h"
#include "tcpup/up.h"

#define TCP_MAXOLEN 40
#define min(a, b) ((a) < (b)? (a): (b))

/*
 * Parse TCP options and place in tcpupopt.
 */
int tcpup_dooptions(struct tcpupopt *to, u_char *cp, int cnt)
{
	static char _null_[] = {0};
	int opt, optlen, oldcnt = cnt;
	to->to_flags = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {
			case TCPOPT_MAXSEG:
				if (optlen != TCPOLEN_MAXSEG)
					continue;
				to->to_flags |= TOF_MSS;
				bcopy((char *)cp + 2,
						(char *)&to->to_mss, sizeof(to->to_mss));
				to->to_mss = ntohs(to->to_mss);
				break;
/*
			case TCPOPT_WINDOW:
				if (optlen != TCPOLEN_WINDOW)
					continue;
				to->to_flags |= TOF_SCALE;
				to->to_wscale = (cp[2] < 14? cp[2]: 14);
				break;
			case TCPOPT_TIMESTAMP:
				if (optlen != TCPOLEN_TIMESTAMP)
					continue;
				to->to_flags |= TOF_TS;
				bcopy((char *)cp + 2,
						(char *)&to->to_tsval, sizeof(to->to_tsval));
				to->to_tsval = ntohl(to->to_tsval);
				bcopy((char *)cp + 6,
						(char *)&to->to_tsecr, sizeof(to->to_tsecr));
				to->to_tsecr = ntohl(to->to_tsecr);
				break;
			case TCPOPT_SACK_PERMITTED:
				if (optlen != TCPOLEN_SACK_PERMITTED)
					continue;
				to->to_flags |= TOF_SACKPERM;
				break;
*/
			case TCPOPT_DESTINATION:
				fprintf(stderr, "TCPOPT_DESTINATION\n");
				to->to_flags |= TOF_DESTINATION;
				to->to_dsaddr = cp + 2;
				to->to_dslen = optlen;
				break;

			case TCPOPT_SACK:
				if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)
					continue;
				to->to_flags |= TOF_SACK;
				to->to_nsacks = (optlen - 2) / TCPOLEN_SACK;
				to->to_sacks = cp + 2;
				break;
			default:
				continue;
		}
	}

	return sizeof(tcpuphdr) + oldcnt;
}

int tcpup_addoptions(struct tcpupopt *to, u_char *optp)
{
	u_int mask, optlen = 0;

	for (mask = 1; mask < TOF_MAXOPT; mask <<= 1) {
		if ((to->to_flags & mask) != mask)
			continue;
		if (optlen == TCP_MAXOLEN)
			break;
		switch (to->to_flags & mask) {
			case TOF_MSS:
				while (optlen % 4) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_MAXSEG)
					continue;
				optlen += TCPOLEN_MAXSEG;
				*optp++ = TCPOPT_MAXSEG;
				*optp++ = TCPOLEN_MAXSEG;
				to->to_mss = htons(to->to_mss);
				bcopy((u_char *)&to->to_mss, optp, sizeof(to->to_mss));
				optp += sizeof(to->to_mss);
				break;
			case TOF_SCALE:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_WINDOW)
					continue;
				optlen += TCPOLEN_WINDOW;
				*optp++ = TCPOPT_WINDOW;
				*optp++ = TCPOLEN_WINDOW;
				*optp++ = to->to_wscale;
				break;
			case TOF_SACK:
				{
					int sackblks = 0;
					struct sackblk *sack = (struct sackblk *)to->to_sacks;
					tcp_seq sack_seq;

					while (!optlen || optlen % 4 != 2) {
						optlen += TCPOLEN_NOP;
						*optp++ = TCPOPT_NOP;
					}
					if (TCP_MAXOLEN - optlen < TCPOLEN_SACKHDR + TCPOLEN_SACK)
						continue;
					optlen += TCPOLEN_SACKHDR;
					*optp++ = TCPOPT_SACK;
					sackblks = min(to->to_nsacks,
							(TCP_MAXOLEN - optlen) / TCPOLEN_SACK);
					*optp++ = TCPOLEN_SACKHDR + sackblks * TCPOLEN_SACK;
					while (sackblks--) {
						sack_seq = (sack->start);
						bcopy((u_char *)&sack_seq, optp, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						sack_seq = (sack->end);
						bcopy((u_char *)&sack_seq, optp, sizeof(sack_seq));
						optp += sizeof(sack_seq);
						optlen += TCPOLEN_SACK;
						sack++;
					}
					break;
				}
			case TOF_TS:
			case TOF_SACKPERM:
				break;
			case TOF_DESTINATION:
				while (!optlen || optlen % 2 != 1) {
					optlen += TCPOLEN_NOP;
					*optp++ = TCPOPT_NOP;
				}
				if (TCP_MAXOLEN - optlen < TCPOLEN_DESTINATION + to->to_dslen)
					continue;
				optlen += (to->to_dslen + TCPOLEN_DESTINATION);
				*optp++ = TCPOPT_DESTINATION;
				*optp++ = (to->to_dslen + TCPOLEN_DESTINATION);
				memcpy(optp, to->to_dsaddr, to->to_dslen);
				optp += to->to_dslen;
				break;

			default:
				/* (0, "unknown TCP option type"); */
				assert(0);
				break;
		}
	}

	/* Terminate and pad TCP options to a 4 byte boundary. */
	if (optlen % 4) {
		optlen += TCPOLEN_EOL;
		*optp++ = TCPOPT_EOL;
	}
	/*
	 * According to RFC 793 (STD0007):
	 * "The content of the header beyond the End-of-Option option
	 * must be header padding (i.e., zero)."
	 * and later: "The padding is composed of zeros."
	 */
	while (optlen % 4) {
		optlen += TCPOLEN_PAD;
		*optp++ = TCPOPT_PAD;
	}

	return (optlen);
}


