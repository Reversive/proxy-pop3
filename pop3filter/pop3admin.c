// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <pop3admin.h>

static bool cmp_str(uint8_t * str1, uint8_t * str2, uint8_t size);
static enum response_stats admin_parse_request(t_admin_req * request, uint8_t * buffer, size_t buff_len);

static void send_admin_resp(int fd, uint8_t status, char * message, struct sockaddr_storage client_addr, size_t client_addr_len);
static void stats_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);
static void get_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);
static void set_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);
static void get_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);
static void set_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);
static void get_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);
static void set_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len);

static int filter_cmd_size = 0;
static int error_file_size = 0;

static void(* admin_actions[COMMAND_SIZE])(int, int, struct t_admin_req *, struct sockaddr_storage, size_t) = {
    stats_handler, get_timeout_handler, set_timeout_handler, get_filter_handler, 
    set_filter_handler, get_error_handler, set_error_handler
};

static char * failure_messages[COMMAND_SIZE - 1] = {
    "UNSUPPORTED COMMAND", "UNSUPPORTED VERSION", "INVALID ARGUMENTS", "UNAUTHORIZED", "INTERNAL ERROR"
};

void admin_parse(struct selector_key* key) {
    uint8_t buffer[DGRAM_SIZE];
	struct sockaddr_storage client_address;
	int read_chars;
    unsigned int len = sizeof(client_address);
    
	read_chars = recvfrom(key->fd, buffer, DGRAM_SIZE, 0, (struct sockaddr *) &client_address, &len);
    if(read_chars <= 0) {
        log(ERROR, "%s", "Error reading datagram");
        return;
    }

    t_admin_req request;
    enum response_stats status = admin_parse_request(&request, buffer, read_chars);

    if (status != OK) {
        send_admin_resp(key->fd, status, failure_messages[status-1], client_address, len);
        return;
    }

    admin_actions[request.command](key->fd, read_chars, &request, client_address, len);
}

void admin_destroy() {
    if (filter_cmd_size > 0)
        free(proxy_config->pop3_filter_command);

    if (error_file_size > 0)
        free(proxy_config->error_file_path);
}

static enum response_stats admin_parse_request(t_admin_req * request, uint8_t * buffer, size_t buff_len) {
    if (buff_len < HEADER_SIZE + ADMIN_LINE_END_LEN)
        return INVALID_ARGS;
    
    if (!cmp_str(buffer, ADMIN_VERSION, VERSION_SIZE))
        return UNSUPPORTED_VERSION;
    
    memcpy(request->version, buffer, VERSION_SIZE);
    buffer += VERSION_SIZE;

    if (!cmp_str(buffer, ADMIN_TOKEN, TOKEN_SIZE))
        return UNAUTHORIZED;

    memcpy(request->version, buffer, TOKEN_SIZE);
    buffer += TOKEN_SIZE;
    if ((uint8_t) *buffer >= COMMAND_SIZE)
        return UNSOPPORTED_COMMAND;
    
    request->command = (uint8_t) *buffer;
    buffer++;

    memcpy(request->data, buffer, buff_len - HEADER_SIZE - ADMIN_LINE_END_LEN);
    buffer += buff_len - HEADER_SIZE - ADMIN_LINE_END_LEN;
    if (!cmp_str(buffer, ADMIN_LINE_END, ADMIN_LINE_END_LEN))
        return INVALID_ARGS;

    return OK;
}

static void send_admin_resp(int fd, uint8_t status, char * message, struct sockaddr_storage client_addr, size_t client_addr_len) {
    char resp[DGRAM_SIZE];
    ssize_t len = snprintf(resp, DGRAM_SIZE, "%s%c%s%s", ADMIN_VERSION_STR, (char) status, message, ADMIN_LINE_END_STR);
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

static void stats_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len) {
    char resp[DATA_SIZE] = {0};
    if (snprintf((char *) resp, DATA_SIZE,  
            "HISTORIC CONNECTIONS: %zu\nCURRENT CONNECTIONS: %zu\nTRANSFERRED BYTES: %zu",
            historic_connections, current_connections, transferred_bytes) < 0) {
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}

static void get_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len){
    char resp[DATA_SIZE] = {0};
    if (snprintf(resp , DATA_SIZE, "TIMEOUT: %f", client_timeout) < 0){
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}

static void set_timeout_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len){
    char tmp[DATA_SIZE] = {0};

    if (request_len == HEADER_SIZE + ADMIN_LINE_END_LEN) {
        send_admin_resp(fd, INVALID_ARGS, "MISSING DATA", client_addr, client_addr_len);
        return;
    }
    
    for (int i = 0; i < DATA_SIZE - 1 && request->data[i] != '\r'; i++)
        tmp[i] = (char) request->data[i];

    client_timeout = atof(tmp);
    send_admin_resp(fd, OK, "CHANGED TIMEOUT", client_addr, client_addr_len);
}

static void get_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len){
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


static void set_filter_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len){
    if (request_len == HEADER_SIZE + ADMIN_LINE_END_LEN) { 
        send_admin_resp(fd, INVALID_ARGS, "MISSING DATA", client_addr, client_addr_len);
        return;
    }

    if (filter_cmd_size == 0) {
        proxy_config->pop3_filter_command = malloc(request_len - HEADER_SIZE - ADMIN_LINE_END_LEN);
        if (proxy_config->pop3_filter_command == NULL) {
            send_admin_resp(fd, INTERNAL_ERROR, "ERROR ALLOCATING MEMORY FOR CMD", client_addr, client_addr_len);
            return;
        }
        filter_cmd_size = request_len - HEADER_SIZE - ADMIN_LINE_END_LEN;
    } else if (filter_cmd_size < request_len - HEADER_SIZE - ADMIN_LINE_END_LEN) {
        void * aux = realloc(proxy_config->pop3_filter_command, request_len - HEADER_SIZE - ADMIN_LINE_END_LEN);
        if (aux == NULL) {
            send_admin_resp(fd, INTERNAL_ERROR, "ERROR ALLOCATING MEMORY FOR CMD", client_addr, client_addr_len);
            return;
        }
        proxy_config->pop3_filter_command = aux;
        filter_cmd_size = request_len - HEADER_SIZE - ADMIN_LINE_END_LEN;
    }

    int i;
    for (i = 0; i < request_len - HEADER_SIZE - ADMIN_LINE_END_LEN - 1 && request->data[i] != '\r'; i++)
        proxy_config->pop3_filter_command[i] = (char) request->data[i];

    proxy_config->pop3_filter_command[i] = 0;

    send_admin_resp(fd, OK, "CHANGED FILTER PROGRAM", client_addr, client_addr_len);
}

static void get_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len){
    char resp[DATA_SIZE] = {0};
    if (snprintf(resp, DATA_SIZE, "ERROR FILE: %s", proxy_config->error_file_path) < 0) {
        send_admin_resp(fd, INTERNAL_ERROR, "ERROR CREATING RESPONSE", client_addr, client_addr_len);
        return;
    }

    send_admin_resp(fd, OK, resp, client_addr, client_addr_len);
}

static void set_error_handler(int fd, int request_len, struct t_admin_req * request, struct sockaddr_storage client_addr, size_t client_addr_len){
    if (request_len == HEADER_SIZE + ADMIN_LINE_END_LEN) { 
        send_admin_resp(fd, INVALID_ARGS, "MISSING DATA", client_addr, client_addr_len);
        return;
    }

    if (error_file_size == 0) {
        proxy_config->error_file_path = malloc(request_len - HEADER_SIZE - ADMIN_LINE_END_LEN);
        if (proxy_config->error_file_path == NULL) {
            send_admin_resp(fd, INTERNAL_ERROR, "ERROR ALLOCATING MEMORY FOR PATH", client_addr, client_addr_len);
            return;
        }
        error_file_size = request_len - HEADER_SIZE - ADMIN_LINE_END_LEN;
    } else if (error_file_size < request_len - HEADER_SIZE - ADMIN_LINE_END_LEN) {
        void * aux = realloc(proxy_config->error_file_path, request_len - HEADER_SIZE - ADMIN_LINE_END_LEN);
        if (aux == NULL) {
            send_admin_resp(fd, INTERNAL_ERROR, "ERROR ALLOCATING MEMORY FOR PATH", client_addr, client_addr_len);
            return;
        }
        proxy_config->error_file_path = aux;
        filter_cmd_size = request_len - HEADER_SIZE - ADMIN_LINE_END_LEN;
    }

    int i;
    for (i = 0; i < request_len - HEADER_SIZE - ADMIN_LINE_END_LEN - 1 && request->data[i] != '\r'; i++)
        proxy_config->error_file_path[i] = (char) request->data[i];

    proxy_config->error_file_path[i] = 0;

    send_admin_resp(fd, OK, "CHANGED ERROR FILE", client_addr, client_addr_len);
}


