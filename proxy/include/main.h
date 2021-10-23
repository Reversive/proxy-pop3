#ifndef MAIN_H
#define MAIN_H
#include "parse_options.h"
#include "selector.h"
#include "pop3_handler.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <errno.h>

#define QUEUE_SIZE 20
#define SELECTOR_ELEMENTS 1024
#define STDIN 0
enum STATES {ERROR = -1, SUCCESS = 0};

extern proxy_configuration_ptr proxy_conf;

#endif