/*	$Id: proxyarp.c 60411 2013-05-13 10:17:53Z ryo $	*/

/*
 * Copyright (c) 1984, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Sun Microsystems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

#include <sys/param.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet/if_inarp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <syslog.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <time.h>
#include <err.h>
#include <errno.h>
#include <signal.h>

#include "proxyarp.h"

#undef PROXYARP_STRESS_DEBUG
#undef PROXYARP_RELOAD_SIGINFO
#undef RTMSG_DEBUG

#ifdef PROXYARP_STRESS_DEBUG
#define PROXYARP_KEVENT_TIMEOUT	5		/* debug */
#define PROXYARP_ROUTE_DELETE_INTERVAL	5	/* debug */
#else
#define PROXYARP_KEVENT_TIMEOUT		10
#define PROXYARP_ROUTE_DELETE_INTERVAL	30
#endif /* PROXYARP_STRESS_DEBUG */


#ifndef RT_ROUNDUP
#define RT_ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#endif
#ifndef RT_ADVANCE
#define RT_ADVANCE(x, n) (x += RT_ROUNDUP((n)->sa_len))
#endif

int main(int, char *[]);
static int usage(void);
static int proxyarp_main(void);
static int delete_interface_route(const char *ifname, struct in_addr *);

static int rtmsg_proc(struct rt_msghdr *, size_t);
static int load_config(void);
struct iflist_item *iflist_append(char *);
struct iflist_item *iflist_exists(char *);
int iflist_deleteall(void);
int iflist_count(void);
static void sighandler(int);
static int pidfile_or_hup(const char *);
static void pidfile_delete(void);

static int proxyarp_debug = 0;
static int conf_loaded = 0;
static int check_routing_table = 0;
static int check_routing_socket = 0;

struct proxyarp_conf confroot = TAILQ_HEAD_INITIALIZER(confroot);

struct iflist_item {
	LIST_ENTRY(iflist_item) list;
	int fd;
	char ifname[IF_NAMESIZE + 1];
};

LIST_HEAD(, iflist_item) iflist;

const char *confpath = PATH_PROXYARP_CONF;
int verbose;
int sighup;
int sigterm;

pid_t pid;

unsigned int bpfbufsize = BPFBUFSIZE;
unsigned char bpfbuf[BPFBUFSIZE];


static int
usage()
{
	fprintf(stderr, "usage: proxyarpd [options]\n");
	fprintf(stderr, "	-f <file>	Load the rules containd in file.\n");
	fprintf(stderr, "	-D		Run in debug mode, with all the output to stderr,\n");
	fprintf(stderr, "			and will not detach and does not become a daemon.\n");
	fprintf(stderr, "	-s		check routing socket and delete illegal arp table\n");
	fprintf(stderr, "	-r		check routing table periodically and delete illegal arp table\n");
	return 99;
}

void
logging(int prio, char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (proxyarp_debug) {
		vfprintf(stderr, fmt, ap);
		printf("\n");
	} else {
		vsyslog(prio, fmt, ap);
	}
	va_end(ap);
}

struct iflist_item *
iflist_append(char *str)
{
	size_t len;
	struct iflist_item *elm;

	/* already exists? */
	if ((elm = iflist_exists(str)) != NULL)
		return elm;

	len = strlen(str);
	if (len == 0)
		return NULL;

	elm = malloc(sizeof(struct iflist_item));
	if (elm == NULL)
		return NULL;

	memset(elm, 0, sizeof(*elm));
	strncpy(elm->ifname, str, IFNAMSIZ);
	LIST_INSERT_HEAD(&iflist, elm, list);

	return elm;
}

struct iflist_item *
iflist_exists(char *str)
{
	struct iflist_item *elm;

	LIST_FOREACH(elm, &iflist, list) {
		if (strcmp(elm->ifname, str) == 0)
			return elm;
	}
	return NULL;
}

int
iflist_count()
{
	int n;
	struct iflist_item *elm;

	n = 0;
	LIST_FOREACH(elm, &iflist, list) {
		n++;
	}

	return n;
}

int
iflist_deleteall()
{
	struct iflist_item *elm;
	while ((elm = LIST_FIRST(&iflist)) != NULL) {
		LIST_REMOVE(elm, list);
		free(elm);
	}
	return 0;
}

static int getifname(uint16_t, char *, size_t);

static int
getifname(uint16_t ifindex, char *ifname, size_t l)
{
	static struct ifaddrs* ifaddrs = NULL;

	int i;
	struct ifaddrs *addr;
	const struct sockaddr_dl *sdl = NULL;

	if (ifaddrs == NULL) {
		i = getifaddrs(&ifaddrs);
		if (i != 0) {
			logging(LOG_ERR, "getifaddrs: %s", strerror(errno));
			return -1;
		}
	}

	for (addr = ifaddrs; addr; addr = addr->ifa_next) {
		if (addr->ifa_addr == NULL || 
		    addr->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (const struct sockaddr_dl *)(void *)addr->ifa_addr;
		if (sdl && sdl->sdl_index == ifindex) {
			strlcpy(ifname, addr->ifa_name, l);
			return 0;
		}
	}

	return -1;
}

static int
delete_interface_route(const char *ifname, struct in_addr *addr)
{
	static struct timespec ts0;
	struct timespec ts1;
	size_t needed;
	char ifnamebuf[IFNAMSIZ];
	char hbuf[NI_MAXHOST];
	char *lim, *buf, *next;
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sina;
	struct sockaddr_dl *sdl;
	int mib[6] = {
		CTL_NET,
		PF_ROUTE,
		0,
		AF_INET,
		NET_RT_FLAGS,
		RTF_LLINFO
	};
	int l, s, rc;

	if ((ifname == NULL) || (addr == NULL)) {
		clock_gettime(CLOCK_MONOTONIC, &ts1);
		if ((ts1.tv_sec - ts0.tv_sec) < PROXYARP_ROUTE_DELETE_INTERVAL)
			return 0;
		ts0 = ts1;
	}

	s = -1;
	rc = 0;

	if (proxyarp_debug)
		logging(LOG_DEBUG, "delete interface route");

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		logging(LOG_ERR, "route-sysctl-estimate");
		return -1;
	}
	if (needed == 0)
		return 0;

	if ((buf = malloc(needed)) == NULL) {
		logging(LOG_ERR, "cannot allocate memory to get arp-table");
		return -1;
	}
	if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
		logging(LOG_ERR, "error in retrieval of routing table");
		return -1;
	}

	lim = buf + needed;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		sina = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)
		    (RT_ROUNDUP(sina->sin_len) + (char *)sina);

		if (rtm->rtm_rmx.rmx_expire == 0)
			continue;
		if (sina->sin_other & SIN_PROXY)
			continue;
		if (rtm->rtm_addrs & RTA_NETMASK) {
			sina = (struct sockaddr_inarp *)
			    (RT_ROUNDUP(sdl->sdl_len) + (char *)sdl);
			if (sina->sin_addr.s_addr == 0xffffffff)
				continue;
			if (sina->sin_len != 8)
				continue;
		}

		if ((sdl->sdl_index == 0) || (getifname(sdl->sdl_index,
		    ifnamebuf, sizeof(ifnamebuf)) != 0))
			continue;


		if ((addr != NULL) && (addr->s_addr != sina->sin_addr.s_addr))
			continue;
		if ((ifname != NULL) && (strcmp(ifname, ifnamebuf) != 0))
			continue;

		if (config_lookup(&confroot, ifnamebuf, &sina->sin_addr) !=
		    NULL) {
			if (proxyarp_debug) {
				if ((addr != NULL) && (ifname != NULL))
					logging(LOG_DEBUG,
					    "delete by one-shot");
				else
					logging(LOG_DEBUG,
					    "delete by scanned");
			}

			/*
			 * delete unexpected arp entry
			 */

			/*
			 * open routing socket if needed,
			 * and delete arp entry
			 */
			if ((s < 0) && (s = socket(PF_ROUTE, SOCK_RAW, 0)) <
			    0) {
				logging(LOG_ERR, "cannot open routing socket");
				rc = -1;
				goto done;
			}

			l = rtm->rtm_msglen;
			rtm->rtm_seq = 0;
			rtm->rtm_type = RTM_DELETE;
			if (write(s, rtm, (size_t)l) < 0) {
				logging(LOG_ERR, "writing routing socket: %s",
				    strerror(errno));
				rc = -1;
				goto done;
			}


		if (getnameinfo((const struct sockaddr *)sdl,
		    (socklen_t)sdl->sdl_len,
		    hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) != 0)
			snprintf(hbuf, sizeof(hbuf), "<invalid>");

			logging(LOG_INFO, "delete arptable: %s at %s on %s",
			    inet_ntoa(sina->sin_addr), hbuf, ifnamebuf);
		}
	}


 done:
	free(buf);
	if (s >= 0)
		close(s);

	return rc;
}


static int
rtmsg_proc(struct rt_msghdr *rtm, size_t size)
{
	char *end;
#ifdef RTMSG_DEBUG
	char logbuf[1024];
#endif
	struct sockaddr_in *sin;

	for (end = (char *)rtm + size; (char *)rtm < end; 
	    rtm = (struct rt_msghdr *)((char *)rtm + rtm->rtm_msglen)) {

		/*
		 * pickup adding arp entry
		 */
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		if (rtm->rtm_type != RTM_ADD)
			continue;

		if ((rtm->rtm_flags & (RTF_UP|RTF_HOST|RTF_LLINFO)) !=
		    (RTF_UP|RTF_HOST|RTF_LLINFO)) {
#ifdef RTMSG_DEBUG
			logging(LOG_DEBUG,
			    "rtm_flags: 0x%x: no arp entry? ignore",
			    rtm->rtm_flags);
#endif
			continue;
		}
		if (rtm->rtm_addrs != (RTA_DST|RTA_GATEWAY|RTA_IFP|RTA_IFA)) {
#ifdef RTMSG_DEBUG
			logging(LOG_DEBUG,
			    "rtm_addrs: 0x%x: no arp entry? ignore",
			    rtm->rtm_addrs);
#endif
			continue;
		}

		{
			int i;
			char *p;
			struct sockaddr *saddr[RTAX_MAX];
			struct sockaddr *sa;
			struct sockaddr_dl *sadl;
			char ifname[IF_NAMESIZE];

#ifdef RTMSG_DEBUG
			printf("====================\n");
			printf("rtm_flags=0x%x\n", rtm->rtm_flags);
			printf("rtm_addrs=0x%x\n", rtm->rtm_addrs);
#endif /* RTMSG_DEBUG */

			p = (char *)(rtm + 1);
			for (i = 0; i < RTAX_MAX; i++) {
				if ((1 << i) & rtm->rtm_addrs) {
					sa = (struct sockaddr *)p;
					saddr[i] = sa;
					RT_ADVANCE(p, sa);
				} else {
					saddr[i] = NULL;
				}
			}

#ifdef RTMSG_DEBUG
			printf("af=%d: ", saddr[RTAX_DST]->sa_family);
			getnameinfo(saddr[RTAX_DST], saddr[RTAX_DST]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_DST: %s\n", logbuf);

			printf("af=%d: ", saddr[RTAX_GATEWAY]->sa_family);
			getnameinfo(saddr[RTAX_GATEWAY],
			    saddr[RTAX_GATEWAY]->sa_len, logbuf,
			    sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_GATEWAY: %s\n", logbuf);

			printf("af=%d: ", saddr[RTAX_IFP]->sa_family);
			getnameinfo(saddr[RTAX_IFP], saddr[RTAX_IFP]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_IFP: %s\n", logbuf);

			printf("af=%d: ", saddr[RTAX_IFA]->sa_family);
			getnameinfo(saddr[RTAX_IFA], saddr[RTAX_IFA]->sa_len,
			    logbuf, sizeof(logbuf), NULL, 0, NI_NUMERICHOST);
			printf("RTAX_IFA: %s\n", logbuf);
#endif /* RTMSG_DEBUG */

			/* extract interface name */
			sadl = (struct sockaddr_dl *)saddr[RTAX_IFP];
			if (sadl->sdl_nlen < sizeof(ifname)) {
				memcpy(ifname, sadl->sdl_data, sadl->sdl_nlen);
				ifname[sadl->sdl_nlen] = '\0';
			}

			/* no need to watch this interface */
			if (iflist_exists(ifname) == NULL)
				continue;

			switch (sadl->sdl_type) {
			case IFT_ETHER:
			/* case IFT_XXX: // other jumbo frame interface */
				break;
			default:
				continue;
			}

			if (saddr[RTAX_DST]->sa_family == AF_INET) {
				struct in_addr src;
				src.s_addr = INADDR_ANY;

				sin = (struct sockaddr_in *)saddr[RTAX_DST];
				if (delete_interface_route(ifname,
				    &sin->sin_addr) < 0)
					return -1;
			}
		}
	}

	return 0;
}

static struct ether_addr *
conflookup(void *confarg, const char *ifname, struct in_addr *addr)
{
	struct proxyarp_entry *entry;

	entry = config_lookup(&confroot, ifname, addr);

	if (entry == NULL)
		return NULL;

	return &entry->ether_addr;
}


static int
proxyarp_main(void)
{
	static const struct timespec tout = { PROXYARP_KEVENT_TIMEOUT, 0 };
#define MAX_BPF	128
	struct kevent kev[MAX_BPF + 1];	/* some BPFs + routing socket */
	struct kevent ev[MAX_BPF + 1];
	struct iflist_item *ifitem;
	int i, kq, nev, nfd, rtsock, ret;
	ssize_t rc;
	static struct {
		struct rt_msghdr rtmsg_rtm;
		char rtmsg_buf[];
	} *rtmsg;
#define RTMSG_BUFSIZE	(1024 * 64)
	struct iflist_item iflist_rtsock;

	ret = -1;
	kq = -1;
	rtmsg = NULL;
	rtsock = -1;

	/*
	 * initialize kevent structure and setup
	 */
	memset(kev, 0, sizeof(kev));
	nfd = 0;

	/* open bpf interfaces, and setup kevent structure */
	if (iflist_count() > MAX_BPF) {
		logging(LOG_ERR, "too many interfaces");
		return -1;
	}

	LIST_FOREACH(ifitem, &iflist, list) {
		if ((ifitem->fd = bpfopen(ifitem->ifname, 0, &bpfbufsize)) < 0)
			continue;
		if (bpf_arpfilter(ifitem->fd) < 0) {
			close(ifitem->fd);
			continue;
		}

		if (proxyarp_debug)
			logging(LOG_DEBUG, "open: bpf: %d on %s", ifitem->fd,
			    ifitem->ifname);

		EV_SET(&kev[nfd], ifitem->fd, EVFILT_READ, EV_ADD | EV_ENABLE,
		    0, 0, (intptr_t)ifitem);
		nfd++;
	}

	if (check_routing_socket) {
		/* open routing socket, and setup kevent structure */
		rtmsg = malloc(RTMSG_BUFSIZE);
		if (rtmsg == NULL) {
			logging(LOG_ERR, "cannot allocate memory");
			goto proxyarp_done;
		}

		memset(&iflist_rtsock, 0, sizeof(iflist_rtsock));
		iflist_rtsock.fd = rtsock = socket(PF_ROUTE, SOCK_RAW, 0);
		if (rtsock == -1) {
			logging(LOG_ERR, "socket: PF_ROUTE: %s",
			    strerror(errno));
			goto proxyarp_done;
		}
		if (proxyarp_debug)
			logging(LOG_DEBUG, "open: rtsock: %d", rtsock);

		EV_SET(&kev[nfd], rtsock, EVFILT_READ, EV_ADD | EV_ENABLE,
		    0, 0, (intptr_t)&iflist_rtsock);
		nfd++;
	}

	if (nfd == 0) {
		if (proxyarp_debug)
			logging(LOG_DEBUG, "no interface");
		pause();
		goto proxyarp_done;
	}

	/*
	 * set kqueue
	 */
	if ((kq = kqueue()) == -1) {
		logging(LOG_ERR, "kqueue: %s", strerror(errno));
		goto proxyarp_done;
	}
	if (kevent(kq, kev, nfd, NULL, 0, NULL) == -1) {
		logging(LOG_ERR, "kevent: %s", strerror(errno));
		goto proxyarp_done;
	}

	/*
	 * daemon loop
	 */
	for (ret = 0;;) {
		if (check_routing_table)
			delete_interface_route(NULL, NULL);

		if (sighup || sigterm)
			goto proxyarp_done;

#ifdef PROXYARP_STRESS_DEBUG
		sighup = 1;
#endif

		nev = kevent(kq, NULL, 0, ev, nfd, &tout);
		if (nev == -1) {
			if (errno == EINTR)
				continue;
			logging(LOG_ERR, "kevent: %s", strerror(errno));
		}
		if (nev == 0) {
			/* timeout */
#ifdef PROXYARP_STRESS_DEBUG
			sighup = 1;
#else
			continue;
#endif
		}

		for (i = 0; i < nev; i++) {
			ifitem = (struct iflist_item *)ev[i].udata;

			if (ifitem->fd == rtsock) {
				rc = read(rtsock, rtmsg, RTMSG_BUFSIZE);
				if (rc <= 0) {
					logging(LOG_ERR, "read: %s",
					    strerror(errno));
					goto proxyarp_done;
				}
				if (rtmsg_proc(&rtmsg->rtmsg_rtm, rc) < 0) {
					goto proxyarp_done;
				}
			} else {
				rc = bpfread_and_arp(conflookup, NULL,
				     ifitem->fd, ifitem->ifname,
				     bpfbuf, bpfbufsize);
			}
		}
	}

 proxyarp_done:
	if (rtmsg != NULL)
		free(rtmsg);
	if (kq > 0)
		close(kq);
	for (i = 0; i < nfd; i++) {
		ifitem = (struct iflist_item *)kev[i].udata;

		if (proxyarp_debug)
			logging(LOG_DEBUG, "close: %d", ifitem->fd);
		close(ifitem->fd);
	}
	return ret;
}

static int
load_config()
{
	struct proxyarp_conf tmpconf;
	struct proxyarp_entry *entry;
	int rc;

	TAILQ_INIT(&tmpconf);
	rc = read_config(confpath, &tmpconf);

	if (++conf_loaded == 0)
		conf_loaded++;	/* incremental load counter */

	/* load OK? */
	if (rc == 0) {
		/* delete main configuration */
		config_deleteall(&confroot);
		iflist_deleteall();

		/* add new configuration from temporary */
		TAILQ_FOREACH(entry, &tmpconf, link) {
			config_addentry(&confroot, entry);
			iflist_append(entry->key.ifname);
		}

		/* delete temporary configuration */
		config_deleteall(&tmpconf);

		if (conf_loaded != 1)
			logging(LOG_INFO, "%s reloaded", confpath);
	}
	return rc;
}

static int
pidfile_or_hup(const char *path)
{
	int fd, rc;
	pid_t pidnum;
	char pidnumbuf[32];

	if ((fd = open(path, O_RDWR|O_CREAT, 0644)) < 0) {
		logging(LOG_ERR, "open: %s: %s", path, strerror(errno));
		return -1;
	}

	/*
	 * lock pid file, or send HUP signal to existing proxyarpd process
	 * and exit myself.
	 */
	if (flock(fd, LOCK_EX|LOCK_NB) < 0) {
		close(fd);
		if ((fd = open(path, O_RDONLY)) < 0) {
			logging(LOG_ERR, "open: %s: %s", path,
			    strerror(errno));
			return -2;
		}

		memset(pidnumbuf, 0, sizeof(pidnumbuf));
		rc = read(fd, pidnumbuf, sizeof(pidnumbuf));
		if (rc < 0) {
			logging(LOG_ERR, "read: %s: %s", path,
			    strerror(errno));
			return -3;
		}

		if ((pidnum = strtol(pidnumbuf, (char **)NULL, 10)) == 0) {
			logging(LOG_ERR, "%s: %s: illegal pid", path,
			    pidnumbuf);
			return -4;
		}

		if (verbose)
			logging(LOG_INFO, "sending HUP signal to %u",
			    (unsigned int)pidnum);

		if (kill(pidnum, SIGHUP) != 0) {
			logging(LOG_ERR, "kill: %u: %s", (unsigned int)pidnum,
			    strerror(errno));
			return -5;
		}

		return 1;
	}

	/* write pid */
	ftruncate(fd, 0); 
	snprintf(pidnumbuf, sizeof(pidnumbuf), "%u\n", (unsigned int)getpid());
	if (write(fd, pidnumbuf, strlen(pidnumbuf)) !=
	    (ssize_t)strlen(pidnumbuf)) {
		logging(LOG_ERR, "write: %s: %s", path, strerror(errno));
		return -1;
	}

	atexit(pidfile_delete);

	return 0;
}

static void
pidfile_delete()
{
	unlink(PATH_PROXYARPD_PID);
}

static void
sighandler(int signo)
{
	switch (signo) {
#ifdef PROXYARP_RELOAD_SIGINFO
	case SIGINFO:
#endif
	case SIGHUP:
		sighup = 1;
		break;
	case SIGTERM:
		sigterm = 1;
		break;
	default:
		break;
	}
}


int
main(int argc, char *argv[])
{
	struct sigaction sa;
	int ch, rc;

	while ((ch = getopt(argc, argv, "Df:rsv")) != -1) {
		switch (ch) {
		case 'D':
			proxyarp_debug = 1;
			break;
		case 'f':
			confpath = optarg;
			break;
		case 'r':
			check_routing_table++;
			break;
		case 's':
			check_routing_socket++;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
		default:
			return usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (!proxyarp_debug)
		openlog("proxyarp", LOG_PID|LOG_NDELAY, LOG_DAEMON);


	/*
	 * load config
	 */
	if (load_config() != 0)
		return 2;
	if (conf_loaded == 0)
		return usage();

	if (!proxyarp_debug) {
		rc = daemon(0, 0);
		if (rc < 0) {
			logging(LOG_ERR, "daemon: %s", strerror(errno));
			return 3;
		}
	}

	/*
	 * create /var/run/proxyarp.pid or send SIGHUP to daemon existing
	 */
	pid = getpid();
	rc = pidfile_or_hup(PATH_PROXYARPD_PID);
	switch (rc) {
	case 0:
		/* pidfile has created */
		break;
	case 1:
		/* pidfile has alread exists. send HUP signal */
		return 1;
	default:
		return 4;
	}

	/*
	 * setup signal handlers
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sighandler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
#ifdef PROXYARP_RELOAD_SIGINFO
	sigaction(SIGINFO, &sa, NULL);
#endif

	/* debug */
	if (proxyarp_debug)
		config_dumpentry(&confroot);

	for (;;) {
		proxyarp_main();	/* would return if any signals */

		if (sigterm)
			break;

		if (sighup) {
			load_config();
			sighup = 0;
		}
	}

	logging(LOG_INFO, "terminated");

	return 0;
}
