#	$Id: Makefile 53242 2012-05-23 10:01:11Z ryo $

PROG=	proxyarpd
SRCS=	proxyarp.c proxyarp_conf.c proxyarp_bpf.c parse.c

NOMAN=	yes

LDADD+=	
DPADD+=	

.include <bsd.prog.mk>
