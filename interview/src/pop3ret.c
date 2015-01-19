#include "server.h"

static
int dispatch_command(FILE *client, char *cmd_line)
{
	char *cmd;
	char *ptr;
	char *args = NULL;

	cmd = cmd_line;

	for (ptr = cmd; *ptr && *ptr != ' ' && *ptr != '\n'; ptr++);

	if (*ptr == ' ') {
		args = ptr + 1;
	}

	*ptr = '\0';

	if (!strcasecmp(cmd, "APOP")) {
		return pop3_apop(client, args);
	} else if (!strcasecmp(cmd, "DELE")) {
		return pop3_dele(client, args);
	} else if (!strcasecmp(cmd, "LIST")) {
		return pop3_list(client, args);
	} else if (!strcasecmp(cmd, "NOOP")) {
		return pop3_noop(client);
	} else if (!strcasecmp(cmd, "PASS")) {
		return pop3_pass(client, args);
	} else if (!strcasecmp(cmd, "QUIT")) {
		return pop3_quit(client);
	} else if (!strcasecmp(cmd, "RETR")) {
		return pop3_retr(client, args);
	} else if (!strcasecmp(cmd, "RSET")) {
		return pop3_rset(client);
	} else if (!strcasecmp(cmd, "STAT")) {
		return pop3_stat(client);
	} else if (!strcasecmp(cmd, "TOP")) {
		return pop3_top(client, args);
	} else if (!strcasecmp(cmd, "UIDL")) {
		return pop3_uidl(client, args);
	} else if (!strcasecmp(cmd, "USER")) {
		return pop3_user(client, args);
	} else if (*cmd) {
		fprintf(client, "-ERR command not found: %s\r\n", cmd);
		fflush(client);
	}

	return 0;
}

static
int handle_client(int fd)
{
	char *line = NULL;
	size_t size;
	size_t nread;
	FILE *client;

	if ((client = fdopen(fd, "w+")) == NULL) {
		perror("fdopen");
		return 1;
	}

	pop3_init(client);

	while (1)
	{
		if ((nread = getline(&line, &size, client)) == -1) {
			return 1;
		}

		if (nread && line[nread - 1] == '\n') {
			line[nread - 1] = '\0';
		}

		if (dispatch_command(client, line)) {
			free(line);
			break;
		}

		free(line);
		line = NULL;
	}

	fclose(client);

	return 0;
}

int main(int argc, const char **argv)
{
	int rc;
	int opt;
	int sockfd;
	int clientfd;
	pid_t pid;
	struct sockaddr_in saddr = {0};

	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		fputs("Failed to set SIGCHLD handler.", stderr);
		return 1;
	}

	sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (sockfd == -1) {
		perror("socket");
		return 1;
	}

	opt = 1;

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
	               sizeof(opt)) != 0) {
		perror("setsockopt");
		return 1;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr.sin_port = htons(CHALL_PORT);

	if (bind(sockfd, (struct sockaddr *) &saddr,
	         sizeof(saddr)) != 0) {
		perror("bind");
		return 1;
	}

	if (listen(sockfd, 20) != 0) {
		perror("listen");
		return 1;
	}

	while (1)
	{
		clientfd = accept(sockfd, NULL, NULL);

		if (clientfd == -1) {
			perror("accept");
			continue;
		}

		pid = fork();

		if (pid == -1) {
			perror("fork");
			close(clientfd);
			continue;
		}

		if (pid == 0) {
			alarm(TIMEOUT);

			close(sockfd);

			rc = drop_privs(CHALL_USER);

			if (rc == 0) {
				rc = handle_client(clientfd);
			}

			close(clientfd);
			_exit(rc);
		}

		close(clientfd);
	}

	return 0;
}
