#include <error.h>
#include <limits.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#ifndef PIDFS_IOCTL_MAGIC
#define PIDFS_IOCTL_MAGIC 0xFF
#endif
#ifndef PIDFD_BORROW_GROUPS
#define PIDFD_BORROW_GROUPS                   _IO(PIDFS_IOCTL_MAGIC, 11)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_err(MSG, ...)                                                   \
	fprintf(stderr, "(%s:%d: errno: %s) " MSG "\n", __FILE__, __LINE__, \
		clean_errno(), ##__VA_ARGS__)

static void child_die()
{
	exit(1);
}

static int cmsg_recv(int fd)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	struct iovec iov;
	int data = 0;
	char control[CMSG_SPACE(sizeof(int))] = { 0 };
	int rcv_fd = -1;
	int err;

	iov.iov_base = &data;
	iov.iov_len = sizeof(data);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	err = recvmsg(fd, &msg, 0);
	if (err < 0) {
		log_err("recvmsg");
		return -1;
	}

	if (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		log_err("recvmsg: truncated");
		return -1;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		log_err("no control msg");
		return -1;
	}
	if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
		if (cmsg->cmsg_len < sizeof(rcv_fd)) {
			log_err("CMSG parse: SCM_RIGHTS wrong len");
			return -1;
		}
		memcpy(&rcv_fd, CMSG_DATA(cmsg), sizeof(rcv_fd));
	}

	/* send(pfd, "x", sizeof(char), 0) */
	if (data != 'x') {
		log_err("recvmsg: data corruption");
		return -1;
	}

	return rcv_fd;
}

struct sock_addr {
	char sock_name[32];
	struct sockaddr_un listen_addr;
	socklen_t addrlen;
};

static void fill_sockaddr(struct sock_addr *addr, bool abstract)
{
	char *sun_path_buf = (char *)&addr->listen_addr.sun_path;

	addr->listen_addr.sun_family = AF_UNIX;
	addr->addrlen = offsetof(struct sockaddr_un, sun_path);
	strncpy(addr->sock_name, "scm_pidfd_server", sizeof(addr->sock_name));
	addr->addrlen += strlen(addr->sock_name);
	if (abstract) {
		*sun_path_buf = '\0';
		addr->addrlen++;
		sun_path_buf++;
	}
	memcpy(sun_path_buf, addr->sock_name, strlen(addr->sock_name));
}

int main(void)
{
	int cfd;
	int rcv_fd;
	int err;
	struct sock_addr server_addr;
	uid_t euid;
	gid_t egid;

	cfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cfd < 0) {
		log_err("socket");
		child_die();
	}

	fill_sockaddr(&server_addr, 0);

	if (connect(cfd, (struct sockaddr *)&server_addr.listen_addr,
		    server_addr.addrlen) != 0) {
		log_err("connect");
		child_die();
	}

	rcv_fd = cmsg_recv(cfd);
	if (rcv_fd == -1) {
		log_err("fd recv failed");
		child_die();
	}
	printf("got fd %i\n", rcv_fd);
	euid = geteuid();
	egid = getegid();
	err = setreuid(euid, euid);
	if (err) {
		log_err("setreuid() failed");
		child_die();
	}
	err = setregid(egid, egid);
	if (err) {
		log_err("setregid() failed");
		child_die();
	}
	system("id");
	err = ioctl(rcv_fd, PIDFD_BORROW_GROUPS, 0);
	if (err) {
		log_err("ioctl failed");
		child_die();
	}
	system("id");
	err = send(cfd, "x", 1, 0);
	if (err != 1) {
		log_err("send failed");
		child_die();
	}

	return 0;
}
