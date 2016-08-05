/*	$Id: proxyarp_bpf.c 53336 2012-05-31 12:03:07Z ryo $	*/

/*-
 *
 * Copyright (c) 2012 Internet Initiative Japan Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/if_arp.h>
#include <net/if_ether.h>
#include <net/bpf.h>
#include <net/route.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <ctype.h>

#include "proxyarp.h"

#undef PROXYARP_DEBUG

/* ethernet arp packet */
struct arppkt {
	struct ether_header eheader;
	struct {
		uint16_t ar_hrd;
		uint16_t ar_pro;
		uint8_t ar_hln;
		uint8_t ar_pln;
		uint16_t ar_op;
		uint8_t ar_sha[ETHER_ADDR_LEN];
		struct in_addr ar_spa;
		uint8_t ar_tha[ETHER_ADDR_LEN];
		struct in_addr ar_tpa;
	} arp;
};

static int bpfslot(void);
#ifdef PROXYARP_DEBUG
static void dumpstr(const uint8_t *, size_t);
#endif
static void reply_arp(struct ether_addr *(*)(void *, const char *,
                      struct in_addr *), void *, int, const char *,
                      struct arppkt *, uint32_t);

struct bpf_insn arp_filter[] = {
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, (ETHER_ADDR_LEN * 2)),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_ARP, 0, 3),
	/* arphdr->ar_op */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, ETHER_HDR_LEN + 6),
	/* ar_op == ARPOP_REQUEST */
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, -1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static int
bpfslot()
{
	int fd, i;

#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR);
#else
	char devbpf[PATH_MAX + 1];

	memset(devbpf, 0, PATH_MAX + 1);
	i = 0;
	do {
		snprintf(devbpf, sizeof(devbpf), "/dev/bpf%d", i++);
		fd = open(devbpf, O_RDWR);
	} while ((fd < 0) && (errno == EBUSY));
#endif

	return fd;
}

int
bpf_arpfilter(int fd)
{
	struct bpf_program bpfprog;

	memset(&bpfprog, 0, sizeof(bpfprog));
	bpfprog.bf_len = __arraycount(arp_filter);
	bpfprog.bf_insns = arp_filter;
	ioctl(fd, BIOCSETF, &bpfprog);

	return 0;
}

int
bpfopen(const char *ifname, int promisc, unsigned int *buflen)
{
	int fd, flag;
	struct ifreq ifr;
	struct bpf_version bv;

	fd = bpfslot();
	if (fd < 0) {
		logging(LOG_ERR, "open: bpf: %s", strerror(errno));
		goto bpfopen_err;
	}

	if (ioctl(fd, BIOCVERSION, (caddr_t)&bv) < 0) {
		logging(LOG_ERR, "ioctl: BIOCVERSION: %s", strerror(errno));
		goto bpfopen_err;
	}

	if (bv.bv_major != BPF_MAJOR_VERSION ||
	    bv.bv_minor < BPF_MINOR_VERSION) {
		logging(LOG_ERR, "kernel bpf filter out of date");
		goto bpfopen_err;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (ifname != NULL) {
		strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
		if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
			logging(LOG_ERR, "ioctl: %s: BIOCSETIF: %s", ifname,
			    strerror(errno));
			goto bpfopen_err;
		}
	}

	flag = 1;
	ioctl(fd, BIOCIMMEDIATE, &flag);

	if (promisc)
		ioctl(fd, BIOCPROMISC, 0);

	ioctl(fd, BIOCSBLEN, buflen);
	ioctl(fd, BIOCGBLEN, buflen);

	return fd;

 bpfopen_err:
	if (fd >= 0)
		close(fd);

	return -1;
}

int
getifinfo(const char *ifname, int *mtu, uint8_t *hwaddr)
{
	int mib[6] = {
		CTL_NET,
		AF_ROUTE,
		0,
		AF_LINK,
		NET_RT_IFLIST,
		0
	};
	uint8_t *buf, *end, *msghdr;
	struct if_msghdr *ifm;
	struct if_data *ifd = NULL;
	struct sockaddr_dl *sdl;
	size_t len;
	int rc;

	rc = -1;
	buf = NULL;
	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		logging(LOG_ERR, "sysctl: %s: cannot get iflist size",
		    strerror(errno));
		goto getifinfo_done;
	}
	if ((buf = malloc(len)) == NULL) {
		logging(LOG_ERR, "cannot allocate memory");
		goto getifinfo_done;
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		logging(LOG_ERR, "sysctl: %s: cannot get iflist",
		    strerror(errno));
		goto getifinfo_done;
	}

	end = buf + len;
	for (msghdr = buf; msghdr < end; msghdr += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)msghdr;
		if (ifm->ifm_type == RTM_IFINFO) {
			sdl = (struct sockaddr_dl *)(ifm + 1);

			if (sdl->sdl_type != IFT_ETHER)
				continue;
			if (strncmp(&sdl->sdl_data[0], ifname, sdl->sdl_nlen)
			    != 0)
				continue;


			ifd = &ifm->ifm_data;
			if (mtu != NULL)
				*mtu = ifd->ifi_mtu;
			memcpy(hwaddr, LLADDR(sdl), ETHER_ADDR_LEN);
			rc = 0;
			break;
		}
	}
	if (rc != 0)
		logging(LOG_ERR,
		    "%s: Not a ethernet interface or no such interface",
		    ifname);

 getifinfo_done:
	if (buf != NULL)
		free(buf);

	return rc;
}

#ifdef PROXYARP_DEBUG
static void
dumpstr(const uint8_t *str, size_t len)
{
	const unsigned char *p = (const unsigned char*)str;
	size_t i = len;
	char ascii[17];
	char *ap = ascii;

	while (i > 0) {
		unsigned char c;

		if (((len - i) & 15) == 0) {
			printf("%08x:", len - i);
			ap = ascii;
		}

		c = p[len - i];
		printf(" %02x", c);
		i--;

		*ap++ = isprint(c) ? c : '.';

		if (((len - i) & 15) == 0) {
			*ap = '\0';
			printf("  %s\n", ascii);
		}
	}
	*ap = '\0';

	if (len & 0xf) {
		const char *whitesp =
		 /* "00 01 02 03 04 05 06 07:08 09 0A 0B 0C 0D 0E 0F " */
		    "                                                ";
		i = len % 16;
		printf("%s  %s\n", whitesp + (i * 3), ascii);
	}
}
#endif /* PROXYARP_DEBUG */

static void
reply_arp(struct ether_addr *(*lookupfunc)(void *, const char *,
    struct in_addr *), void *lookuparg, int fd, const char *ifname,
    struct arppkt *arp, uint32_t size)
{
	char etherbuf1[sizeof("XX:XX:XX:XX:XX:XX")];
	char etherbuf2[sizeof("XX:XX:XX:XX:XX:XX")];
	char inetbuf1[sizeof("255.255.255.255")];
	char inetbuf2[sizeof("255.255.255.255")];
	struct arppkt areply;
	struct ether_addr *srcmac;
	static const uint8_t eth_broadcast[ETHER_ADDR_LEN] =
	    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

#ifdef PROXYARP_DEBUG
	printf("arp request packet\n");
	dumpstr((uint8_t *)arp, size);
#endif

	/* checking destination ether addr is broadcast */
	if ((ntohs(arp->eheader.ether_type) != ETHERTYPE_ARP) ||
	    memcmp(arp->eheader.ether_dhost, eth_broadcast, ETHER_ADDR_LEN) ||
	    (ntohs(arp->arp.ar_hrd) != ARPHRD_ETHER) ||
	    (ntohs(arp->arp.ar_pro) != ETHERTYPE_IP) ||
	    (arp->arp.ar_hln != ETHER_ADDR_LEN) ||
	    (arp->arp.ar_pln != sizeof(struct in_addr)) ||
	    (ntohs(arp->arp.ar_op) != ARPOP_REQUEST))
		return;	/* not an arp request packet */

	srcmac = lookupfunc(lookuparg, ifname, (struct in_addr *)&arp->arp.ar_tpa);
	if (srcmac == NULL)
		return;	/* entry not found in config */

	/* build arp reply packet */
	memset(&areply, 0, sizeof(areply));
	memcpy(&areply.eheader.ether_dhost, arp->arp.ar_sha, ETHER_ADDR_LEN);
	memcpy(&areply.eheader.ether_shost, srcmac->ether_addr_octet,
	    ETHER_ADDR_LEN);
	areply.eheader.ether_type = htons(ETHERTYPE_ARP);
	areply.arp.ar_hrd = htons(ARPHRD_ETHER);
	areply.arp.ar_pro = htons(ETHERTYPE_IP);
	areply.arp.ar_hln = ETHER_ADDR_LEN;
	areply.arp.ar_pln = sizeof(struct in_addr);
	areply.arp.ar_op = htons(ARPOP_REPLY);
	memcpy(&areply.arp.ar_sha, srcmac->ether_addr_octet,
	    ETHER_ADDR_LEN);
	memcpy(&areply.arp.ar_spa, &arp->arp.ar_tpa, sizeof(struct in_addr));
	memcpy(areply.arp.ar_tha, arp->arp.ar_sha, ETHER_ADDR_LEN);
	memcpy(&areply.arp.ar_tpa, &arp->arp.ar_spa, sizeof(struct in_addr));

#ifdef PROXYARP_DEBUG
	dumpstr((uint8_t *)&areply, sizeof(areply));
#endif

	/* send an arp-reply via bpf */
	write(fd, &areply, sizeof(areply));

	/* for logging */
	strlcpy(inetbuf1, inet_ntoa(areply.arp.ar_spa), sizeof(inetbuf1));
	strlcpy(etherbuf1, ether_ntoa((struct ether_addr *)areply.arp.ar_sha), sizeof(etherbuf1));
	strlcpy(inetbuf2, inet_ntoa(areply.arp.ar_tpa), sizeof(inetbuf2));
	strlcpy(etherbuf2, ether_ntoa((struct ether_addr *)areply.arp.ar_tha), sizeof(etherbuf2));
	logging(LOG_INFO, "arp reply %s at %s on %s to %s %s",
	    inetbuf1, etherbuf1, ifname, inetbuf2, etherbuf2);
}

int
bpfread_and_arp(struct ether_addr *(*lookupfunc)(void *, const char *,
    struct in_addr *), void *lookuparg, int fd, const char *ifname,
    unsigned char *buf, int buflen)
{
	ssize_t rc;

	rc = read(fd, buf, buflen);
	if (rc == 0) {
		logging(LOG_ERR, "bpfread: no data");
	} else if (rc < 0) {
		logging(LOG_ERR, "bpfread: %s", strerror(errno));
	} else {
		uint8_t *p = buf;
		uint8_t *end = p + rc;

		while (p < end) {
			unsigned int perpacketsize =
			    ((struct bpf_hdr*)p)->bh_hdrlen +
			    ((struct bpf_hdr*)p)->bh_caplen;

			reply_arp(lookupfunc, lookuparg,
			    fd, ifname, (struct arppkt *)((uint8_t *)p +
			    ((struct bpf_hdr*)p)->bh_hdrlen),
			    ((struct bpf_hdr*)p)->bh_datalen);

			p += BPF_WORDALIGN(perpacketsize);
		}
	}

	return 0;
}
