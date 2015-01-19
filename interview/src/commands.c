#include "server.h"

#define INVALID_ARGUMENTS       "-ERR invalid arguments\r\n"
#define ALREADY_AUTHENTICATED   "-ERR already authenticated -__-\"\r\n"

static user_t g_user;

static
int pop3_authenticated(FILE *client)
{
	if (g_user.session_state != SESSION_AUTHENTICATED) {
		ffprintf(client, "-ERR authentication required mofo\r\n");
		return 0;
	}

	return 1;
}

static
int is_locked(const char *username)
{
	int fd;
	char *path;
	int ret = 1;
	char buf[8];

	path = xmalloc(sizeof(TMPDIR) + strlen(username) + sizeof(LOCK_FILE) + 3);
	sprintf(path, "%s/%s/", TMPDIR, username);

	mkdir(path, S_IRWXU | S_IRGRP | S_IWGRP);

	strcat(path, LOCK_FILE);

	if ((fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) != -1) {
		memset(buf, 0, 8);

		if (read(fd, &buf, 8) > 0) {
			if (kill(atoi(buf), 0) == 0) {
				goto cleanup;
			}

			lseek(fd, SEEK_SET, 0);
		}

		sprintf(buf, "%d", getpid());
		write(fd, buf, strlen(buf));
		ret = 0;
	}

cleanup:
	free(path);
	close(fd);

	return ret;
}

static
msg_t *find_msg(unsigned id)
{
	msg_t *msg;

	msg = g_user.messages;

	while (msg)
	{
		if (msg->id == id) {
			if (msg->deleted) {
				return NULL;
			}

			return msg;
		}

		msg = msg->next;
	}

	return NULL;
}

static
int open_msg(msg_t *msg)
{
	int fd;
	char *path;

	path = xmalloc(sizeof(TMPDIR) + strlen(g_user.username) +
	               sizeof(msg->uidl) + 3);
	sprintf(path, "%s/%s/%s", TMPDIR, g_user.username, msg->uidl);

	if ((fd = open(path, O_RDONLY)) == -1) {
		perror("open");
		_exit(1);
	}

	free(path);

	return fd;
}

static
size_t get_total_size(void)
{
	size_t total_size = 0;
	msg_t *msg;

	msg = g_user.messages;

	while (msg) {
		if (!msg->deleted) {
			total_size += msg->size;
		}

		msg = msg->next;
	}

	return total_size;
}

static inline
void read_message_header(msg_t *msg)
{
	size_t count = 0;
	char *ptr;
	char c;
	int fd;

	fd = open_msg(msg);

	ptr = msg->top_block->text;

	while (count != msg->size) {
		if (read(fd, &c, 1) != 1) {
			return;
		}

		if (count + 2 >= msg->top_block->size) {
			if (msg->top_block->size + TOP_CHUNK_SIZE > msg->size) {
				msg->top_block->size = msg->size;
			} else {
				msg->top_block->size += TOP_CHUNK_SIZE;
			}
			msg->top_block->text = realloc(msg->top_block->text, msg->top_block->size);
			ptr = msg->top_block->text + count;
		}

		*ptr++ = c;
		count++;

		if (count >= 4 && *((unsigned int*) (ptr - 4)) == 0x0A0D0A0D) {
			*ptr = '\0';
			msg->top_block->header_size = ptr - msg->top_block->text;
			close(fd);
			return;
		}
	}

	/* Error: invalid headers */
	_exit(1);
}

unsigned get_top_lines(FILE *client, msg_t *msg, unsigned linecount)
{
	unsigned lines = 0;
	unsigned count;
	char *ptr;
	char *limit;
	char c;
	int fd;

	/* Headers */

	ptr = msg->top_block->text + msg->top_block->header_size;
	limit = ptr + msg->top_block->size;

	/* Read as many lines as available */

	while (lines < linecount &&
		   lines < msg->top_block->linecount &&
		   ptr < limit)
	{
		for (; *ptr != '\n' && ptr < limit; ptr++);
		lines++;
		ptr++;
	}

	/* Already have read everything we need */

	if (lines == linecount) {
		return ptr - msg->top_block->text;
	}

	/* Need to read more lines */

	fd = open_msg(msg);
	lseek(fd, ptr - msg->top_block->text, SEEK_SET);

	count = ptr - msg->top_block->text;

	while (lines < linecount) {
		do {
			if (read(fd, &c, 1) != 1) {
				goto end;
			}

			if (count + 2 >= msg->top_block->size) {
				if (msg->top_block->size + TOP_CHUNK_SIZE > msg->size) {
					msg->top_block->size = msg->size;
				} else {
					msg->top_block->size += TOP_CHUNK_SIZE;
				}

				msg->top_block->text = realloc(msg->top_block->text, msg->top_block->size);
				ptr = msg->top_block->text + count;
			}

			*ptr++ = c;
			count++;
		} while (c != '\n');

		msg->top_block->linecount++;
		lines++;
	}

end:
	close(fd);

	return count;
}

static
int datesort(const struct dirent **a, const struct dirent **b)
{
	struct stat statbuf_a;
	struct stat statbuf_b;
	int res;

	if (stat((*a)->d_name, &statbuf_a) || stat((*b)->d_name, &statbuf_b)) {
		return 0;
	}

	res = statbuf_a.st_mtim.tv_sec - statbuf_b.st_mtim.tv_sec;

	if (res != 0) {
		return res;
	}

	return statbuf_a.st_mtim.tv_nsec < statbuf_b.st_mtim.tv_nsec;
}

static
int pop3_get_info(const char *username)
{
	unsigned id = 0;
	char *path;
	struct stat statbuf;
	struct dirent *ent;
	msg_t *prev_msg;
	msg_t *msg;
	unsigned len;
	struct dirent **namelist;
	int n;
	char *cwd;

	len = sizeof(TMPDIR) + strlen(username) + 2;

	path = xmalloc(len);
	sprintf(path, "%s/%s", TMPDIR, username);

	if ((cwd = getcwd(NULL, 64)) == NULL) {
		perror("getcwd");
		_exit(1);
	}

	if (chdir(path)) {
		perror("chdir");
		_exit(1);
	}

	len += UIDL_SIZE + 1;

	if ((n = scandir(path, &namelist, NULL, datesort)) >= 0) {
		prev_msg = g_user.messages;

		while (n--) {
			ent = namelist[n];

			if (strlen(ent->d_name) != UIDL_SIZE - 1) {
				free(ent);
				continue;
			}

			if (stat(ent->d_name, &statbuf) || ((statbuf.st_mode & S_IFMT) != S_IFREG)) {
				free(ent);
				continue;
			}

			msg = xmalloc(sizeof(msg_t));

			msg->id = id;
			msg->deleted = 0;
			msg->size = statbuf.st_size;
			msg->top_block = xmalloc(sizeof(top_block_t));
			msg->top_block->header_size = 0;
			msg->top_block->size = 0;
			msg->top_block->linecount = 0;
			msg->top_block->text = NULL;
			msg->prev = prev_msg;
			msg->next = NULL;

			strncpy(msg->uidl, ent->d_name, UIDL_SIZE);

			if (prev_msg) {
				prev_msg->next = msg;
			} else {
				g_user.messages = msg;
			}

			prev_msg = msg;
			id++;

			free(ent);
		}

		g_user.msg_count = id;

		free(namelist);
	}

	if (chdir(cwd)) {
		perror("chdir");
		_exit(1);
	}

	free(path);
	free(cwd);

	return 1;
}

static
int pop3_doauth(FILE *client, const char *user, const char *password)
{
	struct sockaddr_un address;
	int  sockfd;
	FILE *f;
	const char *ptr;
	char c;
	int res = 0;
	int i;

	for (ptr = user; *ptr; ptr++) {
		c = *ptr;

		if ((c > '0' && c <= '9') || (c >= 'a' && c <= 'z') || // bug, should be c >= '0'...
			(c >= 'A' && c <= 'Z')) {
			continue;
		}

		ffprintf(client, "-ERR invalid username\r\n");
		return 0;
	}

	for (i = 0; i < 32; i++) {
		c = password[i];

		if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		    (c >= 'A' && c <= 'F')) {
			continue;
		}

		ffprintf(client, "-ERR invalid password\r\n");
		return 0;
	}

	address.sun_family = AF_UNIX;
    strcpy(address.sun_path, AUTHENTICATION_SERVER);

	if (((sockfd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) ||
	   (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) == -1)) {

		if (sockfd) {
			close(sockfd);
		}

		ffprintf(client, "-ERR cannot connect to the authentication service\r\n");
		return 0;
	}

	if ((f = fdopen(sockfd, "w+")) == NULL) {
		perror("fdopen");
		return 0;
	}

	ffprintf(f, "check_auth:%s:%s:%s\n", user, g_user.secret, password);

    if (read(sockfd, &c, 1) != 1) {
		ffprintf(client, "-ERR no response from the authentication service\r\n");
	} else {
		if (c) {
			if (!is_locked(user)) {
				pop3_get_info(user);
				res = 1;
			} else {
				ffprintf(client, "-ERR maildrop already locked\r\n");
			}
		} else {
			ffprintf(client, "-ERR invalid password\r\n");
		}
	}

	fclose(f);

	return res;
}

int pop3_init(FILE *client)
{
	char hostname[100] = {0};

	g_user.username = NULL;
	g_user.session_state = SESSION_ANONYMOUS;
	g_user.msg_count = 0;
	g_user.messages = NULL;
	g_user.messages = NULL;

	if ((gethostname(hostname, sizeof(hostname) - 1) == -1) ||
	    (snprintf(g_user.secret, USER_SECRET_MAX_SIZE - 1, "<%u.%u@%s>",
	              getpid(), (unsigned) time(NULL), hostname) < 0)) {
		return 1;
	}

	ffprintf(client, "+OK POP3 server ready %s\r\n", g_user.secret);

	return 0;
}

int pop3_apop(FILE *client, char *args)
{
	char *user;
	char *hash;
	char *ptr;

	if (g_user.session_state == SESSION_AUTHENTICATED) {
		ffprintf(client, ALREADY_AUTHENTICATED);
		return 0;
	}

	user = args;

	if (user) {
		for (ptr = user; *ptr && *ptr != ' '; ptr++);
	}

	if (!user || !*ptr || !*(ptr + 1)) {
		ffprintf(client, INVALID_ARGUMENTS);
		return 0;
	}

	*ptr = '\0';

	hash = ptr + 1;

	if (pop3_doauth(client, user, hash)) {
		if (g_user.username) {
			free(g_user.username);
		}

		ffprintf(client, "+OK maildrop has %u message%s (%zu octets)\r\n",
				 g_user.msg_count, g_user.msg_count > 1 ? "s" : "",
				 get_total_size());

		g_user.username = xmalloc(strlen(user) + 1);
		strcpy(g_user.username, user);
		g_user.session_state = SESSION_AUTHENTICATED;
	} else {
		g_user.session_state = SESSION_ANONYMOUS;
	}

	return 0;
}

int pop3_dele(FILE *client, char *args)
{
	unsigned id;
	msg_t *msg;

	if (!pop3_authenticated(client)) {
		return 0;
	}

	if (!args || !*args) {
		ffprintf(client, INVALID_ARGUMENTS);
		return 0;
	}

	id = atoi(args);
	msg = g_user.messages;

	while (msg) {
		if (msg->id == id) {
			if (msg->deleted) {
				ffprintf(client, "-ERR message %u already deleted\r\n", id);
				return 0;
			}

			msg->deleted = 1;

			if (msg->top_block) {
				if (msg->top_block->text) {
					free(msg->top_block->text);
				}
				free(msg->top_block);
			}

			g_user.msg_count--;

			ffprintf(client, "+OK message %u deleted\r\n", id);

			return 0;
		}

		msg = msg->next;
	}

	ffprintf(client, "-ERR no such message\r\n");

	return 0;
}

int pop3_list(FILE *client, char *args)
{
	msg_t *msg;
	size_t total_size;

	if (!pop3_authenticated(client)) {
		return 0;
	}

	/* No args provided, scan listing */

	if (!args || !*args) {
		total_size = get_total_size();

		ffprintf(client, "+OK %u messages (%zu octets)\r\n",
				 g_user.msg_count, total_size);

		msg = g_user.messages;

		while (msg) {
			if (!msg->deleted) {
				ffprintf(client, "%u %zu\r\n",  msg->id, msg->size);
			}

			msg = msg->next;
		}

		return 0;
	}

	/* Argument provided */

	if ((msg = find_msg(atoi(args))) != NULL) {
		ffprintf(client, "%u %zu\r\n", msg->id, msg->size);
		return 0;
	}

	ffprintf(client, "-ERR no such message\r\n");

	return 0;
}

int pop3_noop(FILE *client)
{
	if (!pop3_authenticated(client)) {
		return 0;
	}

	ffprintf(client, "+OK cool story bro\r\n");

	return 0;
}

int pop3_pass(FILE *client, char *password)
{
	if (g_user.session_state == SESSION_AUTHENTICATED) {
		ffprintf(client, ALREADY_AUTHENTICATED);
		return 0;
	}

	ffprintf(client, "-ERR plaintext authentication is forbidden\r\n");

	return 0;
}

int pop3_quit(FILE *client)
{
	msg_t *msg;
	char *path;
	int ret = 0;

	/* Remove messages */

	msg = g_user.messages;

	path = xmalloc(sizeof(TMPDIR) + strlen(g_user.username) +
	               sizeof(msg->uidl) + 3);

	while (msg) {
		if (msg->deleted) {
			sprintf(path, "%s/%s/%s", TMPDIR, g_user.username, msg->uidl);
			ret |= unlink(path);
		}

		msg = msg->next;
	}

	free(path);

	/* Release lock */

	path = xmalloc(sizeof(TMPDIR) + strlen(g_user.username) +
				   sizeof(LOCK_FILE) + 3);
	sprintf(path, "%s/%s/%s", TMPDIR, g_user.username, LOCK_FILE);
	unlink(path);

	free(path);

	/* Exit */

	if (ret == 0) {
		if (g_user.msg_count) {
			ffprintf(client, "+OK POP3 server signing off (%u messages left)\r\n",
					 g_user.msg_count);
		} else {
			ffprintf(client, "+OK POP3 server signing off (maildrop empty)\r\n");
		}

	} else {
		ffprintf(client, "-ERR some deleted messages not removed\r\n");
	}

	return 1;
}

int pop3_retr(FILE *client, char *args)
{
	msg_t *msg;
	char buf[RETR_BUF_SIZE];
	ssize_t n;
	int fd;

	if (!pop3_authenticated(client)) {
		return 0;
	}

	if (!args || !*args) {
		ffprintf(client, INVALID_ARGUMENTS);
		return 0;
	}

	if ((msg = find_msg(atoi(args))) != NULL) {
		fd = open_msg(msg);

		ffprintf(client, "+OK message follows\r\n");

		while ((n = read(fd, &buf, sizeof(buf))) != 0) {
			fwrite(buf, n, 1, client);
		}

		ffprintf(client, "\r\n.\r\n");

		close(fd);

		return 0;
	}

	ffprintf(client, "-ERR no such message\r\n");

	return 0;
}

int pop3_rset(FILE *client)
{
	msg_t *msg;
	size_t total_size = 0;
	unsigned count = 0;

	if (!pop3_authenticated(client)) {
		return 0;
	}

	msg = g_user.messages;

	while (msg) {
		if (msg->deleted) {
			msg->deleted = 0;
		}

		total_size += msg->size;
		count++;
		msg = msg->next;
	}

	g_user.msg_count = count;

	ffprintf(client, "+OK maildrop has %u messages (%zu octets)\r\n",
			 count, total_size);

	return 0;
}

int pop3_stat(FILE *client)
{
	if (!pop3_authenticated(client)) {
		return 0;
	}

	ffprintf(client, "+OK %u %zu\r\n", g_user.msg_count, get_total_size());

	return 0;
}

int pop3_top(FILE *client, char *args)
{
	int linecount;
	msg_t *msg;
	char *ptr;
	char c;
	unsigned len;

	if (!pop3_authenticated(client)) {
		return 0;
	}

	if (!args || !*args) {
		goto invalid_arguments;
	}

	for (ptr = args; *ptr && *ptr != ' '; ptr++);

	if (!*ptr) {
		goto invalid_arguments;
	}

	*ptr = 0;
	linecount = atoi(ptr + 1);

	if (linecount < 0) {
		goto invalid_arguments;
	}

	if ((msg = find_msg(atoi(args))) != NULL) {
		ffprintf(client, "+OK top of message follows\r\n");

		if (!msg->top_block) {
			msg->top_block = xmalloc(sizeof(top_block_t));
			msg->top_block->header_size = 0;
			msg->top_block->size = 0;
			msg->top_block->linecount = 0;
			msg->top_block->text = NULL;
		}

		if (!msg->top_block->text) {
			read_message_header(msg);
		}

		len = get_top_lines(client, msg, linecount);
		c = msg->top_block->text[len];
		msg->top_block->text[len] = '\0';

		fwrite(msg->top_block->text, 1, len, client);
		ffprintf(client, "\r\n.\r\n");

		msg->top_block->text[len] = c;

		return 0;
	} else {
		ffprintf(client, "-ERR no such message\r\n");
		return 0;
	}

invalid_arguments:
	ffprintf(client, INVALID_ARGUMENTS);
	return 0;
}

int pop3_uidl(FILE *client, char *args)
{
	msg_t *msg;

	if (!pop3_authenticated(client)) {
		return 0;
	}

	/* No args provided, scan listing */

	if (!args || !*args) {
		msg = g_user.messages;

		ffprintf(client, "+OK\r\n");

		while (msg) {
			if (!msg->deleted) {
				ffprintf(client, "%u %s\r\n",  msg->id, msg->uidl);
			}

			msg = msg->next;
		}

		return 0;
	}

	/* Argument provided */

	if ((msg = find_msg(atoi(args))) != NULL) {
		ffprintf(client, "%u %s\r\n", msg->id, msg->uidl);
		return 0;
	}

	ffprintf(client, "-ERR no such message, only %u messages in maildrop\r\n",
			 g_user.msg_count);

	return 0;
}

int pop3_user(FILE *client, char *name)
{
	if (g_user.session_state == SESSION_AUTHENTICATED) {
		ffprintf(client, ALREADY_AUTHENTICATED);
		return 0;
	}

	ffprintf(client, "-ERR plaintext authentication is forbidden\r\n");

	return 0;
}
