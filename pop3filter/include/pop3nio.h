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
#include "../utils/include/buffer.h"
#include "../utils/include/stm.h"
#include "../utils/include/netutils.h"
#include "../utils/include/selector.h"
#include "../utils/include/data_structures.h"
#include "../utils/include/logger.h"
#include "../utils/include/parser.h"
#include "../utils/include/parser_utils.h"
#include "../utils/include/queue.h"

#define MAX_CONNECTIONS 250
#define N(x) (sizeof(x)/sizeof((x)[0]))

void pop3_passive_accept(struct selector_key *key);

void init_parser_defs();

void destroy_parser_defs();

extern int server;

#endif //POP3FILTER_POP3NIO_H
