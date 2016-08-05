/*	$Id: proxyarp_conf.c 53242 2012-05-23 10:01:11Z ryo $	*/

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "proxyarp.h"

static void dump_entry(struct proxyarp_entry *);

static void
dump_entry(struct proxyarp_entry *entry)
{
	char tmp1[32];
	char tmp2[32];

	inet_ntop(AF_INET, &entry->key.addr.start, tmp1, sizeof(tmp1));
	inet_ntop(AF_INET, &entry->key.addr.end, tmp2, sizeof(tmp2));

	printf("<%p>\n  interface: %s\n  ranges: %s-%s\n  etheraddr: %s\n",
	    entry,
	    entry->key.ifname,
	    tmp1, tmp2,
	    ether_ntoa(&entry->ether_addr));
}

void
config_dumpentry(struct proxyarp_conf *conf)
{
	struct proxyarp_entry *entry;

	printf("# dumping config %p\n", conf);
	TAILQ_FOREACH(entry, conf, link) {
		dump_entry(entry);
	}
}

int
config_addentry(struct proxyarp_conf *conf, struct proxyarp_entry *entry)
{
	struct proxyarp_entry *elm;

	elm = malloc(sizeof(struct proxyarp_entry));
	if (elm == NULL)
		return -1;

	memcpy(elm, entry, sizeof(*elm));

	TAILQ_INSERT_TAIL(conf, elm, link);

	return 0;
}

struct proxyarp_entry *
config_lookup(struct proxyarp_conf *conf, const char *interface, struct in_addr *addr)
{
	struct proxyarp_entry *entry;

	TAILQ_FOREACH(entry, conf, link) {
		if ((ntohl(entry->key.addr.start.s_addr) <= ntohl(addr->s_addr)) &&
		    (ntohl(addr->s_addr) <= ntohl(entry->key.addr.end.s_addr)) &&
		    (strncmp(interface, entry->key.ifname, sizeof(entry->key.ifname)) == 0)) {

			return entry;
		}
	}

	return NULL;
}

int
config_deleteall(struct proxyarp_conf *conf)
{
	struct proxyarp_entry *entry;

	while ((entry = TAILQ_FIRST(conf)) != NULL) {
		TAILQ_REMOVE(conf, entry, link);
		free(entry);
	}

	return 0;
}
