#ifndef DATA_STRUCTURES_H
#define DATA_STRUCTURES_H

typedef struct proxy_configuration_t {
    char *error_file_path;
    char *pop3_listen_address;
    char *admin_listen_address;
    char *origin_server_address;
    char *pop3_filter_command;

} proxy_configuration;

typedef proxy_configuration * proxy_configuration_ptr;


#endif