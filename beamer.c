/* Copyright 2014 Marc Butler <mockbutler@gmail.com>
 * All Rights Reserved.
 *
 * Example usage:
 *
 *  remote$ beamer 3000 prog &
 *  local$ beamer build prog remote 3000 &
 *
 * Notes:
 *
 *  - Assumes a 32 bit size_t type.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FMODE_DEFAULT 0755
#define S_(M) S__(M)
#define S__(M) #M

static const char *usage =
	"Usage:\n"
	"\tbeamer dir file host port -- transmitter\n"
	"\tbeamer port file -- receiver\n"
	"\n"
	"receiver options\n"
	"\n"
	" -m octal or --mode octal : set the file mode, default " S_(FMODE_DEFAULT) "\n"
	"\n";

static mode_t fmode = FMODE_DEFAULT;

static struct option options[] = {
	{ "mode", required_argument, 0, 0 },
	{ 0, 0, 0, 0 }
};

char* join_path(const char *base, const char *ext)
{
	assert(base && ext);
	assert(*base != 0 || *ext != 0);

	if (strlen(base) == 0)
		return strdup(ext);
	else if (strlen(ext) == 0)
		return strdup(base);

	int add_slash = 0;
	if (base[strlen(base) - 1] != '/') {
		add_slash = 1;
	}

	size_t len = strlen(base) + add_slash + strlen(ext);
	char *path = malloc(len);
	if (path == NULL)
		err(1, "memory error");
	strncpy(path, base, len);
	if (add_slash) {
		path[strlen(path) + 1] = 0;
		path[strlen(path)] = '/';
	}
	strncat(path, ext, len);
	return path;
}

int create_path(const char *path)
{
	char *buf = alloca(strlen(path) + 1);
	const char *slash = path;
	size_t len;
	int err;

	while ((slash = strchr(slash + 1, '/'))) {
		len = slash - path + 1;
		memcpy(buf, path, len);
		buf[len] = 0;
		err = mkdir(buf, 0777);
		if (err)
			return -1;
	}
	return 0;
}

int create_file(const char *path)
{
	int fd;
create_file:
	fd = open(path, O_WRONLY | O_TRUNC | O_CREAT, fmode);
	if (fd == -1 && (errno == ENOENT || errno == ENOTDIR)) {
		int err = create_path(path);
		if (err)
			return err;
		goto create_file;
	}
	return fd;
}

int open_link(const char *server, const char *port)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;

	int ret;
	struct addrinfo *res;
	ret = getaddrinfo(server, port, &hints, &res);
	if (ret)
		errx(1, "getaddrinfo error %s", gai_strerror(ret));
	int sock;
	struct addrinfo *rp;
	for (rp = res; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;
		ret = connect(sock, rp->ai_addr, rp->ai_addrlen);
		if (ret == 0)
			break;
		close(sock);
		sock = -1;
	}
	freeaddrinfo(res);
	return sock;
}

int open_server(const char *port)
{
	struct addrinfo hints;
	struct addrinfo *res, *rp;
	int ret, sock;

	memset(&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	ret = getaddrinfo(NULL, port, &hints, &res);
	if (ret)
		errx(1, "getaddrinfo error %s\n", gai_strerror(ret));

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sock == -1)
			continue;
		if (bind(sock, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(sock);
	}
	freeaddrinfo(res);

	if (rp == NULL)
		errx(1, "failed to bind to port %s\n", port);

	int opt = 1;
	ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (ret)
		errx(1, "Could not set SO_REUSEADDR\n");

	ret = listen(sock, 1);
	if (ret)
		err(1, "listen error port %s\n", port);

	return sock;
}

int accept_connection(int sock)
{
	struct sockaddr caddr;
	socklen_t caddrlen = sizeof(caddr);
	int client;
	client = accept(sock, &caddr, &caddrlen);
	if (client == -1)
		err(1, "error accepting connection");
	return client;
}

void txsize(int sock, size_t sz)
{
	long val;
	val = htonl(sz);
	ssize_t ret;
	ret = send(sock, &val, sizeof(val), 0);
	if (ret == -1)
		err(1, "error transmitting size");
}

int rxsize(int sock, size_t *sz)
{
	long val;
	ssize_t ret;
	ret = recv(sock, &val, sizeof(val), 0);
	if (ret == sizeof(val)) {
		val = ntohl(val);
		*sz = val;
		return 0;
	}
	return ret;
}

void write_file(int sock, size_t sz, const char *path)
{
	int piping[2];
	if (pipe(piping) < 0)
		err(1, "pipe");

	int fd;
	fd = create_file(path);
	if (fd == -1) {
		warn("error creating file %s", path);
		goto cleanup_pipes;
	}

	ssize_t ret;
	size_t recvd;
	recvd = 0;
	while (recvd < sz) {
		ret = splice(sock, NULL, piping[1], NULL, sz - recvd,
			     SPLICE_F_MOVE|SPLICE_F_MORE);
		if (ret == -1) {
			warn("error receiving data");
			goto cleanup_file;
		}

		ret = splice(piping[0], NULL, fd, NULL, ret,
			     SPLICE_F_MOVE|SPLICE_F_MORE);
		if (ret == -1) {
			warn("error writing file %s", path);
			goto cleanup_file;
		}
		recvd += ret;
	}
	printf("received %zu bytes written to %s\n", sz, path);

	ret = chmod(path, fmode);
	if (ret == -1)
		warn("error writing file mode %o\n", fmode);

cleanup_file:
	close(fd);
cleanup_pipes:
	close(piping[0]);
	close(piping[1]);
}

void backup_file(const char *path)
{
	size_t len = strlen(path) + 5;
	char *bakpath;
	bakpath = alloca(len + 1);
	*bakpath = 0;
	strncpy(bakpath, path, len);
	strncat(bakpath, ".prev", len);
	int ret;
	ret = rename(path, bakpath);
	if (ret != 0) 
		err(1, "rename %s %s", path, bakpath);
}

void file_transfer_loop(int sock, char *path, int epfd)
{
	struct epoll_event events[1];
	for (;;) {
		int nfds;
		nfds = epoll_wait(epfd, events, 1, -1);
		if (nfds == -1)
			err(1, "epoll_wait");

		size_t sz;
		sz = 0;
		int ret;
		ret = rxsize(sock, &sz);
		if (ret != 0) {
			warn("error reading file size");
		} else if (sz == 0) {
			puts("zero file size - client disconnect");
			return;
		} else {
			printf("start receiving file %zu bytes\n", sz);
			backup_file(path);
			write_file(sock, sz, path);
		}
	}
}

void receive(char **args)
{
	int sock;
	sock = open_server(args[0]);

	int epfd;
	epfd = epoll_create(1);
	if (epfd == -1)
		err(1, "epoll_create");
	
	for (;;) {
		int client;
		client = accept_connection(sock);
		if (client == -1)
			continue;
		else
			puts("transmitter connected");

		struct epoll_event ev;
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN|EPOLLHUP|EPOLLRDHUP;
		ev.data.fd = client;

		int ret;
		ret = epoll_ctl(epfd, EPOLL_CTL_ADD, client, &ev);
		if (ret == -1)
			err(1, "epoll_ctl: server sock");

		file_transfer_loop(client, args[1], epfd);
		close(client);
	}
	close(sock);
}

void send_file(int sock, const char *path)
{
	struct stat info;
	int ret;
	ret = lstat(path, &info);
	if (ret == -1)
		err(1, "lstat %s", path);
	int fd = open(path, O_RDONLY);
	if (ret == -1)
		err(1, "open %s", path);
	if (info.st_size > 0) {
		ssize_t sent;
		txsize(sock, info.st_size);
		sent = sendfile(sock, fd, NULL, info.st_size);
		if (sent < 0)
			err(1, "sendfile %s", path);
	}
	close(fd);
	printf("transmitting %s %zu\n", path, info.st_size);
}

void transmit(char **args)
{
	int inotify_fd;
	inotify_fd = inotify_init();
	if (inotify_fd == -1)
		err(1, "inotify_init");

	int watch_fd;
	watch_fd = inotify_add_watch(inotify_fd, args[0], IN_CLOSE_WRITE);
	if (watch_fd == -1)
		err(1, "inotify_add_watch");

	int sock;
	sock = open_link(args[2], args[3]);
	if (sock == -1)
		err(1, "failed to connect to receiver");
	puts("connected to receiver");

	char *path;
	path = join_path(args[0], args[1]);

#define INOTIFY_EVBUF_SIZE 50
	char evbuf[(sizeof(struct inotify_event) + 16) * INOTIFY_EVBUF_SIZE];
	for (;;) {
		ssize_t len;
		len = read(inotify_fd, evbuf, sizeof(evbuf));
		if (len < 0)
			err(1, "inotify error");
		ssize_t proc;
		proc = 0;
		while (proc < len) {
			struct inotify_event *ev;
			ev = (struct inotify_event *)&evbuf[proc];
			if (ev->len && strcmp(args[1], ev->name) == 0)
				send_file(sock, path);
			proc += ev->len + sizeof(*ev);
		}
	}

	free(path);
	close(sock);
}

void parse_fmode(const char *mode)
{
	char *end = NULL;
	long int val = strtol(mode, &end, 8);
	if (*end != 0)
		err(1, "invalid file mode %s", optarg);
	fmode = (mode_t)val;
}

int parse_options(int argc, char **argv)
{
	for (;;) {
		int c, option_index;
		c = getopt_long(argc, argv, "hm:", options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			puts(usage);
			exit(0);
			break;
		case 'm':
			parse_fmode(optarg);
			break;
		default:
			puts(usage);
			exit(EXIT_FAILURE);
		}
	}
	return argc - optind;
}

int main(int argc, char **argv)
{
	assert(sizeof(size_t) == sizeof(long));

	int argcnt;
	argcnt = parse_options(argc, argv);
	if (argcnt == 2)
		receive(argv + optind);
	else if (argcnt == 4)
		transmit(argv + optind);
	else
		puts(usage);
	return 0;
}
