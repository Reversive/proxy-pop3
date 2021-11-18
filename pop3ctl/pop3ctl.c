#include <pop3ctl.h>

client_config_ptr client_config;

int main(int argc, char * argv[]) {
    client_config = parse_client_options(argc, argv);
    printf("Client will connect to %s:%d using token %s\n", 
        client_config->admin_server_address, client_config->admin_server_port, client_config->admin_token);
    return 0;
}

