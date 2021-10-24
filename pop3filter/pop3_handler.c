#include "include/pop3_handler.h"

void accept_pop3_connection(struct selector_key *key) {
    struct sockaddr_storage client_address;
    socklen_t client_address_len = sizeof(client_address);
    fd client = accept(key->fd, (struct sockaddr *)&client_address, &client_address_len);
    if(client == -1) {
        fprintf(stderr, "Unable to connect client");
        close(client);
        return;
    } else {
        fprintf(stdout, "Client connected");
    }

    if(selector_fd_set_nio(client) == -1) {
        close(client);
        return;
    }


    // TODO: Crear struct para guardar data de POP3 (origin fd, client fd, read buffer, write buffer, maquina de estado (stm), etc)

}