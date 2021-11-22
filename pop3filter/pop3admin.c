// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <pop3admin.h>
#define MIN_DGRAM_SIZE 14



static bool cmp_str(uint8_t * str1, uint8_t * str2, uint8_t size);

static void send_admin_resp(int fd, int status, char * message, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void stats_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void get_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void set_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void get_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void set_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void get_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);
static void set_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len);

static int filter_cmd_size = 0;
static int error_file_size = 0;

static void(* admin_actions[COMMAND_SIZE])(int, int, struct t_admin_req *, struct sockaddr_in6, size_t) = {
    stats_handler, get_timeout_handler, set_timeout_handler, get_filter_handler, 
    set_filter_handler, get_error_handler, set_error_handler
};

void admin_parse(struct selector_key* key) {
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
        send_admin_resp(key->fd, INVALID_ARGS, "INVALID DATAGRAM LENGTH", client_address, len);
        return;
    }

    t_admin_req * request = (t_admin_req *) buffer;
    if (!cmp_str(ADMIN_VERSION, request->version, 3)) {
        send_admin_resp(key->fd, UNSUPPORTED_VERSION, "INVALID VERSION NUMBER", client_address, len);
        return;
    }

    if (request->command >= COMMAND_SIZE) {
        send_admin_resp(key->fd, UNSOPPORTED_COMMAND, "UNSOPPORTED COMMAND", client_address, len);
        return;
    }

    if (!cmp_str(ADMIN_TOKEN, request->token, 10)) {
        send_admin_resp(key->fd, UNAUTHORIZED, "UNAUTHORIZED", client_address, len);
        return;
    }

    admin_actions[request->command](key->fd, read_chars, request, client_address, len);
}

void admin_destroy() {
    if (filter_cmd_size > 0)
        free(proxy_config->pop3_filter_command);

    if (error_file_size > 0)
        free(proxy_config->error_file_path);
}

static void send_admin_resp(int fd, int status, char * message, struct sockaddr_in6 client_addr, size_t client_addr_len) {
    char resp[DGRAM_SIZE];
    ssize_t len = snprintf(resp, DGRAM_SIZE, "%s%c%s\r\n", ADMIN_VERSION_STR, status, message);
    if (len < 0) {
        log(ERROR, "%s", "Error creating response");
        return;
    }
    if (sendto(fd, resp, len, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(ERROR, "%s", "Error sending response");
}

static bool cmp_str(uint8_t * str1, uint8_t * str2, uint8_t size) {
	for (int i = 0; i < size; i++) {
        if (str1[i] != str2[i]) 
            return false;
    }
    
    return true;
}

static void stats_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len) {
    char resp[DATA_SIZE] = {0};
    if (snprintf((char *) resp, DATA_SIZE,  
            "HISTORIC CONNECTIONS: %ld\nCURRENT CONNECTIONS: %ld\nTRANSFERRED BYTES: %ld",
            historic_connections, current_connections, transferred_bytes) < 0) {
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}

static void get_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    char resp[DATA_SIZE] = {0};
    if (snprintf(resp , DATA_SIZE, "TIMEOUT: %f\r\n", client_timeout)< 0){
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}

static void set_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    char tmp[DATA_SIZE] = {0};

    if (request_len == HEADER_SIZE) {
        send_admin_resp(fd, INVALID_ARGS, "MISSING DATA", client_addr, client_addr_len);
        return;
    }
    
    for (int i = 0; i < DATA_SIZE - 1 && request->data[i] != '\r'; i++)
        tmp[i] = (char) request->data[i];

    client_timeout = atof(tmp);
    send_admin_resp(fd, OK, "CHANGED TIMEOUT", client_addr, client_addr_len);
}

static void get_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    if (proxy_config->pop3_filter_command == NULL) {
        send_admin_resp(fd, OK, "FILTER COMMAND: NONE", client_addr, client_addr_len);
        return;
    }
    
    char resp[DATA_SIZE] = {0};
    if (snprintf(resp, DATA_SIZE, "FILTER COMMAND: %s", proxy_config->pop3_filter_command) < 0) {
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}


static void set_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    if (request_len == HEADER_SIZE) { 
        send_admin_resp(fd, INVALID_ARGS, "MISSING DATA", client_addr, client_addr_len);
        return;
    }

    if (filter_cmd_size == 0) {
        filter_cmd_size = request_len - HEADER_SIZE;
        proxy_config->pop3_filter_command = malloc(request_len - HEADER_SIZE);
    } else if (filter_cmd_size < request_len - HEADER_SIZE) {
        filter_cmd_size = request_len - HEADER_SIZE;
        proxy_config->pop3_filter_command = realloc(proxy_config->pop3_filter_command, request_len - HEADER_SIZE);
    }

    int i;
    for (i = 0; i < request_len - HEADER_SIZE - 1 && request->data[i] != '\r'; i++)
        proxy_config->pop3_filter_command[i] = (char) request->data[i];

    proxy_config->pop3_filter_command[i] = 0;

    send_admin_resp(fd, OK, "CHANGED FILTER PROGRAM", client_addr, client_addr_len);
}

static void get_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    char resp[DATA_SIZE] = {0};
    if (snprintf(resp, DATA_SIZE, "ERROR FILE: %s", proxy_config->error_file_path) < 0) {
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}

static void set_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    if (request_len == HEADER_SIZE) { 
        send_admin_resp(fd, INVALID_ARGS, "MISSING DATA", client_addr, client_addr_len);
        return;
    }

    if (error_file_size == 0) {
        error_file_size = request_len - HEADER_SIZE;
        proxy_config->error_file_path = malloc(request_len - HEADER_SIZE);
    } else if (error_file_size < request_len - HEADER_SIZE) {
        error_file_size = request_len - HEADER_SIZE;
        proxy_config->error_file_path = realloc(proxy_config->error_file_path, request_len - HEADER_SIZE);
    }

    int i;
    for (i = 0; i < request_len - HEADER_SIZE - 1 && request->data[i] != '\r'; i++)
        proxy_config->error_file_path[i] = (char) request->data[i];

    proxy_config->error_file_path[i] = 0;

    send_admin_resp(fd, OK, "CHANGED ERROR FILE", client_addr, client_addr_len);
}


