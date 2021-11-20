#include <pop3admin.h>

void to_lower_str(char* in_str) {
	for (int i = 0; in_str[i]; i++) {
		in_str[i] = tolower(in_str[i]);
	}
}

#define MIN_DGRAM_SIZE 14

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

void stats_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len) {
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
        "%chistoric connections: %ld\ncurrent connections: %ld\ntransferred bytes: %ld\r\n",
         OK, historic_connections, current_connections, transferred_bytes);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void get_timeout_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
        "%ctimeout: %f\r\n",
         OK, client_timeout);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void set_timeout_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    uint8_t resp[DGRAM_SIZE] = {0};
    memcpy(resp, request->version, 3);
    size_t len = snprintf((char *) resp + 3, DGRAM_SIZE - 3, 
        "%c\r\n",
         OK);

    char tmp[DGRAM_SIZE - 13] = {0};

    int i;
    for (i = 0; i < DGRAM_SIZE - 14 && request->data[i] != '\r'; i++) {
        log(DEBUG, "%c", request->data[i]);
        tmp[i] = (char) request->data[i];
    }

    tmp[i] = 0;
    client_timeout = atof(tmp);

    if (sendto(fd, resp, len + 3, 0, (const struct sockaddr *) &client_addr, client_addr_len) < 0)
		log(DEBUG, "%s", "Error sending response");
}

void get_filter_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    //uint8_t resp[DGRAM_SIZE - 4] = {0};
    
    // t_admin_resp response = {
    //     .status = OK,
    //     .data = resp
    // };
    return;
}


void set_filter_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    return;
}

void get_error_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    // uint8_t resp[DGRAM_SIZE - 4] = {0};
    
    // t_admin_resp response = {
    //     .status = OK,
    //     .data = resp
    // };
    return;
}

void set_error_handler(int fd, struct t_admin_req * request, struct sockaddr_in6 client_addr, size_t client_addr_len){
    return;
}

void(* admin_actions[COMMAND_SIZE])(int, struct t_admin_req *, struct sockaddr_in6, size_t) = {stats_handler, get_timeout_handler, 
                        set_timeout_handler, get_filter_handler, set_filter_handler, get_error_handler, set_error_handler};

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
        if (sendto(key->fd, "HOLA!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    t_admin_req * request = (t_admin_req *) buffer;
    set_timeout_handler(key->fd, request, client_address, len);
    return;

    if (!cmp_str(ADMIN_VERSION, request->version, 3)) {
        if (sendto(key->fd, "VERS!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    if (request->command >= COMMAND_SIZE) {
        if (sendto(key->fd, "COMM!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    if (!cmp_str(ADMIN_TOKEN, request->token, 10)) {
        if (sendto(key->fd, "TOKE!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    admin_actions[request->command](key->fd, request, client_address, len);
    
	// if (buffer[read_chars - 1] == '\n') // Por si lo estan probando con netcat, en modo interactivo
	// 	read_chars--;

	// buffer[read_chars] = 0;
	//log(DEBUG, "UDP received: %s", buffer);
	//to_lower_str(buffer);

    //char buffer_out[DGRAM_SIZE] = { 0 };
	// sprintf(buffer_out, "Connections: %d\r\nIncorrect lines: %d\r\nCorrect lines: %d\r\nInvalid datagrams: %d\r\n", 
    //     total_connections, invalid_lines, total_lines - invalid_lines, invalid_datagrams);

    // if (sendto(key->fd, "PERF!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
	// 	log(DEBUG, "%s", "Error sending response");
}
