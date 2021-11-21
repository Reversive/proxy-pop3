#ifndef POP3FILTER_POP3NIO_H
#define POP3FILTER_POP3NIO_H
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <buffer.h>
#include <stm.h>
#include <netutils.h>
#include <selector.h>
#include <data_structures.h>
#include <logger.h>
#include <parser.h>
#include <parser_utils.h>
#include <queue.h>
#include <pop3admin.h>

#define MAX_CONNECTIONS 250
#define N(x) (sizeof(x)/sizeof((x)[0]))

void pop3_passive_accept(struct selector_key *key);

void init_parser_defs();

void destroy_parser_defs();

void pop3_pool_destroy(void);


extern int server_4;
extern int server_6;
#endif //POP3FILTER_POP3NIO_H
