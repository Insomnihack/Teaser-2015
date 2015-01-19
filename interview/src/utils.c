#include "server.h"

int drop_privs(char *username)
{
	struct passwd *pw = getpwnam(username);

	if (pw == NULL) {
		fprintf(stderr, "User %s not found\n", username);
		return 1;
	}

	if (chdir(pw->pw_dir) != 0) {
		perror("chdir");
		return 1;
	}

	if (setgroups(0, NULL) != 0) {
		perror("setgroups");
		return 1;
	}

	if (setgid(pw->pw_gid) != 0) {
		perror("setgid");
		return 1;
	}

	if (setuid(pw->pw_uid) != 0) {
		perror("setuid");
		return 1;
	}

	return 0;
}

ssize_t recvlen(int fd, char *buf, size_t n)
{
	ssize_t rc;
	size_t nread = 0;

	while (nread < n)
	{
		rc = recv(fd, buf + nread, n - nread, 0);

		if (rc == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return -1;
		}

		if (rc == 0) {
			break;
		}

		nread += rc;
	}
	return nread;
}

ssize_t recv_until(int fd, char *buf, size_t n, char stop)
{
	size_t size = 0;
	char c;
	size_t rc;

	while (size < n)
	{
		rc = recv(fd, &c, 1, 0);

		if (rc == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return -1;
		}

		buf[size] = c;

		if (c == stop) {
			buf[size] = '\0';
			break;
		}

		size++;
	}

	return size;
}

ssize_t sendlen(int fd, const char *buf, size_t n)
{
	ssize_t rc;
	size_t nsent = 0;

	while (nsent < n)
	{
		rc = send(fd, buf + nsent, n - nsent, 0);

		if (rc == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				continue;
			}
			return -1;
		}

		nsent += rc;
	}
	return nsent;
}

ssize_t sendstr(int fd, const char *str)
{
	return sendlen(fd, str, strlen(str));
}

void *xmalloc(size_t size)
{
	void *res;

	res = malloc(size);

	if (!res) {
		perror("malloc");
		_exit(1);
	}

	return res;
}
