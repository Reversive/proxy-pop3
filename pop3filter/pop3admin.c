// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <pop3admin.h>
#define MIN_DGRAM_SIZE 14

int filter_cmd_size = 0;
int error_file_size = 0;

static bool cmp_str(uint8_t * str1, uint8_t * str2, uint8_t size) {
	for (int i = 0; i < size; i++) {
        if (str1[i] != str2[i]) 
            return false;
    }
    return true;
}

/*
    STATS = 0,
    GET_TIMEOUT,
    SET_TIMEOUT,
    GET_FILTER_CMD,
    SET_FILTER_CMD,
    GET_ERROR_FILE,
    SET_ERROR_FILE  
*/

void stats_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len) {
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
        "%chistoric connections: %ld\ncurrent connections: %ld\ntransferred bytes: %ld\r\n",
         OK, historic_connections, current_connections, transferred_bytes);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void get_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
        "%ctimeout: %f\r\n", OK, client_timeout);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void set_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, "%c\r\n", OK);

    char tmp[DGRAM_SIZE - 13] = {0};

    int i;
    for (i = 0; i < DGRAM_SIZE - 14 && request->data[i] != '\r'; i++)
        tmp[i] = (char) request->data[i];

    tmp[i] = 0;
    client_timeout = atof(tmp);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void get_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len;
    if (proxy_config->pop3_filter_command != NULL)
        len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
            "%cfilter command: %s\r\n", OK, proxy_config->pop3_filter_command);
    else 
        len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, "%cfilter command: none\r\n", OK);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}


void set_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    if (request_len == 14) { // Missing data
        size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, "%c\r\n", INVALID_ARGS);
        if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, "%c\r\n", OK);

    if (filter_cmd_size == 0) {
        filter_cmd_size = request_len - 13;
        proxy_config->pop3_filter_command = malloc(request_len - 13);
    } else if (filter_cmd_size < request_len - 13) {
        filter_cmd_size = request_len - 13;
        proxy_config->pop3_filter_command = realloc(proxy_config->pop3_filter_command, request_len - 13);
    }

    int i;
    for (i = 0; i < request_len - 14 && request->data[i] != '\r'; i++)
        proxy_config->pop3_filter_command[i] = (char) request->data[i];

    proxy_config->pop3_filter_command[i] = 0;
   
    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void get_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
        "%cerror file: %s\r\n", OK, proxy_config->error_file_path);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void set_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    if (request_len == 14) { // Missing data
        size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, "%c\r\n", INVALID_ARGS);
        if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, "%c\r\n", OK);
    if (error_file_size == 0) {
        error_file_size = request_len - 13;
        proxy_config->error_file_path = malloc(request_len - 13);
    } else if (error_file_size < request_len - 13) {
        error_file_size = request_len - 13;
        proxy_config->error_file_path = realloc(proxy_config->error_file_path, request_len - 13);
    }

    int i;
    for (i = 0; i < request_len - 14 && request->data[i] != '\r'; i++)
        proxy_config->error_file_path[i] = (char) request->data[i];

    proxy_config->error_file_path[i] = 0;

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void(* admin_actions[COMMAND_SIZE])(int, int, struct t_admin_req *, struct sockaddr_in6, size_t) = {stats_handler, get_timeout_handler, 
                        set_timeout_handler, get_filter_handler, set_filter_handler, get_error_handler, set_error_handler};


static void send_admin_error(int fd, int status, char * message, struct sockaddr_in6 client_addr, size_t client_addr_len) {
    char resp[DGRAM_SIZE];
    ssize_t len = snprintf(resp, DGRAM_SIZE, "%s%c%s\r\n", ADMIN_VERSION_STR, status, message);
    if (sendto(fd, resp, len, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(ERROR, "%s", "Error sending response");
}

void admin_parse(struct selector_key* key) {
    log(DEBUG, "%s", "Incoming admin datagram");
    uint8_t buffer[DGRAM_SIZE];
	struct sockaddr_in6 client_address;
	int read_chars;
    unsigned int len = sizeof(client_address);

	read_chars = recvfrom(key->fd, buffer, DGRAM_SIZE, 0, (struct sockaddr*) &client_address, &len);
    if(read_chars <= 0) {
        log(ERROR, "%s", "Error reading datagram");
        return;
    }

    if(read_chars < MIN_DGRAM_SIZE) {
        send_admin_error(key->fd, INVALID_ARGS, "Datagram length", client_address, len);
        return;
    }

    t_admin_req * request = (t_admin_req *) buffer;
    if (!cmp_str(ADMIN_VERSION, request->version, 3)) {
        send_admin_error(key->fd, UNSUPPORTED_VERSION, "Invalid version number", client_address, len);
        return;
    }

    if (request->command >= COMMAND_SIZE) {
        send_admin_error(key->fd, UNSOPPORTED_COMMAND, "Unsopported command", client_address, len);
        return;
    }

    if (!cmp_str(ADMIN_TOKEN, request->token, 10)) {
        send_admin_error(key->fd, UNAUTHORIZED, "Unauthorized", client_address, len);
        return;
    }

    log(DEBUG, "command %d", request->command);
    admin_actions[request->command](key->fd, read_chars, request, client_address, len);
}



void admin_destroy() {
    if (filter_cmd_size > 0)
        free(proxy_config->pop3_filter_command);

    if (error_file_size > 0)
        free(proxy_config->error_file_path);
}
