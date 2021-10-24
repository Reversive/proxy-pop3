#ifndef PROXY_POP3_HANDLER_H
#define PROXY_POP3_HANDLER_H
#include "../utils/include/selector.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>
#include "../utils/include/data_structures.h"

void accept_pop3_connection(struct selector_key * key);

#endif //PROXY_POP3_HANDLER_H
