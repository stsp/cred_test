#define _GNU_SOURCE
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <assert.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_err(MSG, ...)                                                   \
	fprintf(stderr, "(%s:%d: errno: %s) " MSG "\n", __FILE__, __LINE__, \
		clean_errno(), ##__VA_ARGS__)

struct sock_addr {
	char sock_name[32];
	struct sockaddr_un listen_addr;
	socklen_t addrlen;
};

static void fill_sockaddr(struct sock_addr *addr)
{
	char *sun_path_buf = (char *)&addr->listen_addr.sun_path;

	addr->listen_addr.sun_family = AF_UNIX;
	addr->addrlen = offsetof(struct sockaddr_un, sun_path);
	strncpy(addr->sock_name, "scm_credfd_server", sizeof(addr->sock_name));
	addr->addrlen += strlen(addr->sock_name);
	memcpy(sun_path_buf, addr->sock_name, strlen(addr->sock_name));
}

static int set_creds(int cfd)
{
	socklen_t len;
	struct ucred peer_cred;

	len = sizeof(peer_cred);
	if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &peer_cred, &len)) {
		log_err("Failed to get SO_PEERCRED");
		return -1;
	}
	printf("peer uid: %i gid: %i\n", peer_cred.uid, peer_cred.gid);
	if (peer_cred.uid != getuid()) {
		struct passwd *pw = getpwuid(peer_cred.uid);
		int err;

		if (!pw) {
			log_err("getpwuid() failed");
			return -1;
		}
		err = initgroups(pw->pw_name, peer_cred.gid);
		if (err) {
			log_err("initgroups() failed");
			return -1;
		}
		err = setreuid(peer_cred.uid, -1);
		if (err) {
			log_err("setreuid() failed");
			return -1;
		}
	}
	if (peer_cred.gid != getgid()) {
		int err = setregid(peer_cred.gid, -1);
		if (err) {
			log_err("setregid() failed");
			return -1;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int err, rv;
	int pfd;
	int server;
	struct sock_addr server_addr;
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	int myfd;
	int iobuf;
	struct iovec io = {
	    .iov_base = &iobuf,
	    .iov_len = sizeof(iobuf)
	};
	union {         /* Ancillary data buffer, wrapped in a union
	                   in order to ensure it is suitably aligned */
	    char buf[CMSG_SPACE(sizeof(myfd))];
	    struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(myfd));
	iobuf = 0;

	server = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(server != -1);

	fill_sockaddr(&server_addr);
	unlink(server_addr.sock_name);
	umask(0);
	err = bind(server, (struct sockaddr *)&server_addr.listen_addr, server_addr.addrlen);
	assert(err == 0);

	err = listen(server, 1);
	assert(err == 0);

	pfd = accept(server, NULL, NULL);
	assert(pfd != -1);

	set_creds(pfd);
	myfd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	assert(myfd != -1);
	memcpy(CMSG_DATA(cmsg), &myfd, sizeof(myfd));

	err = sendmsg(pfd, &msg, 0);
	assert(err != -1);
	err = recv(pfd, &rv, sizeof(rv), 0);
	assert(err >= 0);
	if (err == 0)
		printf("EOF from client\n");
	if (rv)
		printf("client returned error %i\n", rv);

	close(myfd);
	close(server);
	unlink(server_addr.sock_name);
	return 0;
}
