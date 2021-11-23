#ifndef POP3CTL_H
#define POP3CTL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <admin_utils.h>
#include <stdbool.h>
#include <logger.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


#define MAX_LINE 100

typedef struct client_configuration_t {
    char *      admin_server_address;
    char *      admin_token;
    char *      admin_server_port;
} client_configuration_t;

typedef struct client_configuration_t * client_config_ptr;

#include <pop3ctl_utils.h>



#endif