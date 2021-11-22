#ifndef _SERVER_UTILS_H
#define _SERVER_UTILS_H

#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <logger.h>
#include <stdbool.h>
#include <netutils.h>


#define MAX_PENDING 20

int setup_server_socket(char * listen_addr, int service, unsigned protocol, bool isipv4);

#endif
