#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

#include <stdint.h>
#define VERSION_NUMBER "0.0.0"
typedef struct proxy_configuration_t {
    char *error_file_path;
    char *pop3_listen_address;
    char *admin_listen_address;
    char *origin_server_address;
    char *pop3_filter_command;
    uint16_t origin_server_port;
    uint16_t pop3_listen_port;
    uint16_t admin_listen_port;
} proxy_configuration;

typedef int fd;
typedef proxy_configuration * proxy_configuration_ptr;

extern proxy_configuration_ptr proxy_config;

#endif
