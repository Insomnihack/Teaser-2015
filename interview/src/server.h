#ifndef _SERVER_H
# define _SERVER_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/un.h>
#include <unistd.h>
#include <grp.h>
#include <time.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define CHALL_PORT             42110
#define CHALL_USER             "pop3ret"
#define TIMEOUT                60
#define USER_SECRET_MAX_SIZE   255

#define TOP_CHUNK_SIZE         100
#define UIDL_SIZE              65
#define RETR_BUF_SIZE          0x1000

#define TMPDIR                 "/tmp/mails/"
#define LOCK_FILE              ".locked"

#define SESSION_ANONYMOUS      0
#define SESSION_AUTHENTICATED  1

#define AUTHENTICATION_SERVER  "/tmp/authserver.sock"

#define ffprintf(client, ...)   do { fprintf(client, __VA_ARGS__); fflush(client); } while (0);

typedef struct top_block {
	size_t size;
	size_t linecount;
	char *text;
	size_t header_size;
} top_block_t;

typedef struct message {
	unsigned id;
	char uidl[UIDL_SIZE];
	unsigned short deleted;
	size_t size;
	struct top_block *top_block;
	struct message *prev;
	struct message *next;
} msg_t;

typedef struct {
	char *username;
	char secret[USER_SECRET_MAX_SIZE];
	unsigned short session_state;
	unsigned msg_count;
	msg_t *messages;
} user_t;

int drop_privs(char *username);
ssize_t recvlen(int fd, char *buf, size_t n);
ssize_t recv_until(int fd, char *buf, size_t n, char stop);
ssize_t sendlen(int fd, const char *buf, size_t n);
ssize_t sendstr(int fd, const char *str);
void *xmalloc(size_t size);

int pop3_init(FILE *client);
int pop3_apop(FILE *client, char *args);
int pop3_dele(FILE *client, char *args);
int pop3_list(FILE *client, char *args);
int pop3_noop(FILE *client);
int pop3_pass(FILE *client, char *password);
int pop3_quit(FILE *client);
int pop3_retr(FILE *client, char *msg);
int pop3_rset(FILE *client);
int pop3_stat(FILE *client);
int pop3_top(FILE *client, char *args);
int pop3_uidl(FILE *client, char *msg);
int pop3_user(FILE *client, char *name);

#endif /* _SERVER_H! */
