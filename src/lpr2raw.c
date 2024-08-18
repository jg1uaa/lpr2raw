// SPDX-License-Identifier: WTFPL

#define LOCAL_HOST "localhost"
#define LOCAL_PORT 515

#if __BRIGHTV
#include <basic.h>
#include <bstdio.h>
#include <bstdlib.h>
#include <bstring.h>
#include <bsetjmp.h>
#include <btron/bsocket.h>
#include <tcode.h>
#include <tstring.h>

#define INADDR_NONE 0xffffffff

typedef W socklen_t;
static char ipstr[256] = LOCAL_HOST;
static char queue[64] = {0};

struct hostent *gethostbyname(char *name)
{
	static struct hostent h;
	B tmp[HBUFLEN];

	return so_gethostbyname(name, &h, tmp) < 0 ? NULL : &h;
}

#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>

#define so_accept accept
#define so_bind bind
#define so_close close
#define so_connect connect
#define so_listen listen
#define so_read read
#define so_setsockopt setsockopt
#define so_socket socket
#define so_write write

extern char *optarg;
static char *ipstr = LOCAL_HOST;
static char *queue = NULL;
#endif

static int fd;
static int port = 9100;
static int debug = 0;
static jmp_buf restart_buf;

#define BUFSIZE 16384
static char buf[BUFSIZE];

#define send_ack(d)	send_response(d, 0)
#define send_nak(d)	send_response(d, 1)

#define min(a, b)	(((a) < (b)) ? (a) : (b))

static int create_socket(struct sockaddr_in *addr, char *hostname, int port);

static int send_response(int d, int nak)
{
	unsigned char rsp = nak;

	return (so_write(d, (void *)&rsp,
			 sizeof(rsp)) >= sizeof(rsp)) ? 0 : -1;
}

static int recv_cmd(int d)
{
	unsigned char cmd;

	return (so_read(d, (void *)&cmd,
			sizeof(cmd)) >= sizeof(cmd)) ? cmd : -1;
}

static int recv_until_lf(int d)
{
	int i = 0;
	unsigned char c;

	while (1) {
		if (so_read(d, (void *)&c, sizeof(c)) < sizeof(c))
			return -1;
		if (c == 0x0a)
			break;
		if (i < BUFSIZE -1)
			buf[i++] = c;
	}

	buf[i++] = 0;
	return i;
}

static int recv_file(int d, int d2, long count, int disp)
{
	int len, s, rv = -1;
	unsigned long c, remain;

	s = count < 0;

	for (c = 0; s || c < count; c += len) {
		remain = s ? BUFSIZE : min(BUFSIZE, count - c);

		if ((len = so_read(d, buf, remain)) < 1) {
			if (s) {
				break;
			} else {
				printf("recv_file: read\n");
				goto fin0;
			}
		}

		if (debug && disp) {
			buf[min(remain, BUFSIZE - 1)] = '\0';
			printf("%s", buf);
		}

		if (d2 >= 0)
			so_write(d2, buf, len);
	}

	if (!s) {
		/* check transfer complete */
		if (recv_cmd(d)) {
			printf("recv_file: recv_cmd\n");
			goto fin0;
		}

		send_ack(d);
	}

	if (debug) {
		printf("%ld bytes %s\n",
			c, (d2 < 0) ? "discarded" : "received");
	}

	rv = 0;
fin0:
	return rv;
}

static int do_command2_loop(int d)
{
	int subcmd, len, d2;
	long count;
	struct sockaddr_in addr;

	if ((d2 = create_socket(&addr, ipstr, port)) < 0) {
		printf("do_command2_loop: create_socket\n");
		goto fin0;
	}

	if (so_connect(d2, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("do_command2_loop: connect\n");
		goto fin1;
	}

	while (1) {
		if ((subcmd = recv_cmd(d)) < 0)
			goto fin1;

		if ((len = recv_until_lf(d)) < 0)
			goto fin1;

		if (debug)
			printf("subcmd=%d len=%d arg=%s\n", subcmd, len, buf);

		count = atol(buf);

		/* process subcommands */
		switch (subcmd) {
		case 0x01:	
			send_ack(d);
			/* do nothing */
			break;
		case 0x02:
			send_ack(d);
			if (recv_file(d, -1, count, 1) < 0)
				goto fin1;
			break;
		case 0x03:
			if (!count) {
				send_nak(d);
				goto fin1;
			} else {
				send_ack(d);
				if (recv_file(d, d2, count, 0) < 0)
					goto fin1;
			}
			break;
		default:
			send_nak(d);
			break;
		}
	}

fin1:
	so_close(d2);
fin0:
	/* quit */
	so_close(d);
	so_close(fd);
	longjmp(restart_buf, 0);
	/*NOTREACHED*/
	return -1;
}

static int is_invalid_queue(void)
{
	char *p;

	if ((p = strchr(buf, ' ')) != NULL)
		*p = 0;

	return (queue == NULL || !strlen(queue)) ? 0 : strcmp(buf, queue);
}

static int do_command_loop(int d)
{
	int cmd, len;

	while (1) {
		if ((cmd = recv_cmd(d)) < 0)
			goto fin0;

		if ((len = recv_until_lf(d)) < 0)
			goto fin0;

		if (debug)
			printf("cmd=%d len=%d arg=%s\n", cmd, len, buf);

		if (is_invalid_queue()) {
			send_nak(d);
			continue;
		}

		/* only accept command 02, "Receive a printer job" */
		switch (cmd) {
		case 0x02:
			send_ack(d);
			return do_command2_loop(d);
		default:
			send_nak(d);
			break;
		}
	}

fin0:
	/* quit */
	so_close(d);
	so_close(fd);
	longjmp(restart_buf, 0);
	/*NOTREACHED*/
	return -1;
}

static int create_socket(struct sockaddr_in *addr, char *hostname, int port)
{
	int s;
	struct hostent *h;
	struct in_addr *a;

	if ((s = so_socket(AF_INET, SOCK_STREAM, 0)) < 0)
		goto fin0;

	memset(addr, 0, sizeof(*addr));

	/*
	 * B-right/V(Chokanji)'s so_gethostbyname() does not support
	 * IP address format. If failed, retry with inet_addr()
	 */
	if ((h = gethostbyname(hostname)) != NULL &&
	    h->h_addrtype == AF_INET &&
	    (a = (struct in_addr *)h->h_addr) != NULL)
		addr->sin_addr.s_addr = a->s_addr;
	else
		addr->sin_addr.s_addr = inet_addr(hostname);

	if (addr->sin_addr.s_addr == INADDR_NONE) {
		so_close(s);
		s = -1;
		goto fin0;
	}

	addr->sin_port = htons(port);
	addr->sin_family = AF_INET;
fin0:
	return s;
}

static int do_main(void)
{
	int d, en = 1, rv = -1;
	struct sockaddr_in addr, peer;
	socklen_t peer_len;

	/* create socket */
	if ((fd = create_socket(&addr, LOCAL_HOST, LOCAL_PORT)) < 0) {
		printf("do_main: create_socket\n");
		goto fin0;
	}

	/* wait for connect */
	so_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&en, sizeof(en));
	if (so_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("do_main: bind\n");
		goto fin1;
	}

	if (so_listen(fd, 1) < 0) {
		printf("do_main: listen\n");
		goto fin1;
	}

	peer_len = sizeof(peer);
	if ((d = so_accept(fd, (struct sockaddr *)&peer, &peer_len)) < 0) {
		printf("do_main: accept\n");
		goto fin1;
	}

	if (debug) {
		printf("connected from %s port %d\n",
			inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
	}

	do_command_loop(d);
	rv = 0;

	so_close(d);
fin1:
	so_close(fd);
fin0:
	return rv;
}

#ifdef __BRIGHTV
int main(int argc, TC *argv[])
{
	int i, cmd, help = 0;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] != TK_MINS)
			goto bad_opt;

		cmd = argv[i][1];
		if (cmd == TK_p && (i + 1) < argc) {
			port = tc_atoi(argv[++i]);
		} else if (cmd == TK_a && (i + 1) < argc) {
			tcstoeucs(ipstr, argv[++i]);
		} else if (cmd == TK_q && (i + 1) < argc) {
			tcstoeucs(queue, argv[++i]);
		} else if (cmd == TK_d) {
			debug = 1;
		} else {
bad_opt:
			help = 1;
			break;
		}
	}

	if (help) {
		printf("usage: %S -a [ip address] -p [portnum]\n", argv[0]);
		return -1;
	}

	setjmp(restart_buf);
	return do_main();
}

#else
int main(int argc, char *argv[])
{
	int ch, help = 0;
	char *appname = argv[0];

	while ((ch = getopt(argc, argv, "p:a:q:dh")) != -1) {
		switch (ch) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'a':
			ipstr = optarg;
			break;
		case 'q':
			queue = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		default:
			help = 1;
			break;
		}
	}

	if (help) {
		printf("usage: %s -a [ip address] -p [portnum]\n", appname);
		return -1;
	}

	setjmp(restart_buf);
	return do_main();
}
#endif
