#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>

typedef struct client_configuration_t {
    char *      admin_server_address;
    char *      admin_token;
    uint16_t    admin_server_port;
} client_configuration_t;

typedef struct client_configuration_t * client_config_ptr;

#include <client_utils.h>

#endif