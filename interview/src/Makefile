CC=gcc
CFLAGS=-O -pie -fPIE -fstack-protector-all -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -Wall -Wno-unused-result -m64 -z noexecstack
LDFLAGS=-lcrypto

POP3RET_SRCS = pop3ret.c utils.c commands.c server.h
POP3RET_OBJS = $(POP3RET_SRCS:.c=.o)

all: pop3ret

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

pop3ret: $(POP3RET_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@
	strip $@

.PHONY: clean

clean:
	rm -f *.o
	rm -f pop3ret
