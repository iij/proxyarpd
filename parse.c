/*	$Id: parse.c 60411 2013-05-13 10:17:53Z ryo $	*/

/*-
 * Copyright (c) 1996, 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <arpa/inet.h>
#include "proxyarp.h"

static int parse_config(const char *, size_t, int, char **, struct proxyarp_conf *);
static int parse_address_range(const char *, struct address_range *);

static int
parse_address_range(const char *str, struct address_range *range)
{
	char tmpbuf[128];	/* XXX */
	char *begin, *end;

	strlcpy(tmpbuf, str, sizeof(tmpbuf));
	begin = tmpbuf;
	end = strchr(begin, '-');
	if (end != NULL)
		*end++ = '\0';
	else
		end = begin;

	if (inet_aton(begin, &range->start) == 0)
		return -1;
	if (inet_aton(end, &range->end) == 0)
		return -1;

	return 0;
}

static int
parse_config(const char *file, size_t lineno, int argc, char **argv, struct proxyarp_conf *conf)
{
	struct proxyarp_entry entry;
	struct ether_addr ethaddr, *eth;

	/*
	 * syntax: <interface> <ipaddr or ipaddr-range> [<macaddr>]
	 */
	if (argc < 2) {
		logging(LOG_ERR, "%s:%u: too few arguments", file, (unsigned int)lineno);
		return -1;
	}
	if (argc > 3) {
		logging(LOG_ERR, "%s:%u: too many arguments", file, (unsigned int)lineno);
		return -1;
	}

#if 0
	{
		int i;
		printf("[%s:%u]\n", file, (unsigned int)lineno);
		for (i = 0; i < argc; i++)
			printf("  argv[%d] = <%s>\n", i, argv[i]);
	}
#endif


	/* parse arguments */
	memset(&entry, 0, sizeof(entry));

	strncpy(entry.key.ifname, argv[0], sizeof(entry.key.ifname));
	if (parse_address_range(argv[1], &entry.key.addr) != 0) {
		logging(LOG_ERR, "%s:%u: illegal address range: %s", file, (unsigned int)lineno, argv[1]);
		return -2;
	}

	if (argc >= 3) {
		eth = ether_aton(argv[2]);
		if (eth == NULL) {
			logging(LOG_ERR, "%s:%u: illegal etheraddr: %s", file, (unsigned int)lineno, argv[2]);
			return -3;
		}
		entry.ether_addr = *eth;	/* memcpy(&entry.ether_addr, eth, 6) */
	} else {
		memset(&ethaddr, 0, sizeof(ethaddr));
		if (getifinfo(entry.key.ifname, NULL, ethaddr.ether_addr_octet) != 0)
			return 0;	/* XXX: syntax ok, but interface is unavailable? ignore this interface */

		memcpy(&entry.ether_addr, ethaddr.ether_addr_octet, ETHER_ADDR_LEN);
	}

	config_addentry(conf, &entry);

	return 0;
}

int
read_config(const char *file, struct proxyarp_conf *conf)
{
	FILE *f;
	char *line, *cp, *vp, **argv, **nargv;
	int argc, rval;
	size_t len, lineno;

	if ((f = fopen(file, "r")) == NULL) {
		logging(LOG_ERR, "fopen: %s: %s", file, strerror(errno));
		return 1;
	}

	rval = 0;
	lineno = 0;
	while ((line = fparseln(f, &len, &lineno, "\\\\#", FPARSELN_UNESCALL))
	    != NULL) {

		argc = 0;
		argv = NULL;
		if (len == 0)
			goto end_of_line;

		for (cp = line; cp != NULL; ) {
			while ((vp = strsep(&cp, "\t ")) != NULL && *vp == '\0')
				;
			if (vp == NULL)
				continue;

			if ((nargv = realloc(argv,
			    sizeof(char *) * (argc + 1))) == NULL) {
				logging(LOG_ERR, "no memory to parse %s", file);
				return 1;
			}
			argv = nargv;
			argc++;
			argv[argc - 1] = vp;
		}
		if (argc != 0)
			if (parse_config(file, lineno, argc, argv, conf))
				rval = 1;

 end_of_line:
		if (argv != NULL)
			free(argv);
		free(line);
	}
	fclose(f);

	if (rval)
		logging(LOG_ERR, "%s: configuration error", file);

	return rval;
}
