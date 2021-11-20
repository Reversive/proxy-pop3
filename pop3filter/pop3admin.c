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

void admin_parse(struct selector_key* key) {
    log(DEBUG, "%s", "Incoming admin datagram");
    uint8_t buffer[BUFFSIZE];
	struct sockaddr_in6 client_address;
	int read_chars;
    unsigned int len = sizeof(client_address);

	read_chars = recvfrom(key->fd, buffer, BUFFSIZE, 0, (struct sockaddr*) &client_address, &len);
    if(read_chars < 0) {
        log(ERROR, "%s", "Error reading datagram");
        return;
    }

    if(read_chars < MIN_DGRAM_SIZE) {
        if (sendto(key->fd, "HOLA!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    t_admin_req * request = (t_admin_req *) buffer;
    if (cmp_str(ADMIN_VERSION, request->version, 3)) {
        if (sendto(key->fd, "VERS!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    if (request->command >= COMMAND_SIZE) {
        if (sendto(key->fd, "COMM!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    if (cmp_str(ADMIN_TOKEN, request->token, 10)) {
        if (sendto(key->fd, "TOKE!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		    log(DEBUG, "%s", "Error sending response");

        return;
    }

    
    
	// if (buffer[read_chars - 1] == '\n') // Por si lo estan probando con netcat, en modo interactivo
	// 	read_chars--;

	// buffer[read_chars] = 0;
	//log(DEBUG, "UDP received: %s", buffer);
	//to_lower_str(buffer);

    //char buffer_out[BUFFSIZE] = { 0 };
	// sprintf(buffer_out, "Connections: %d\r\nIncorrect lines: %d\r\nCorrect lines: %d\r\nInvalid datagrams: %d\r\n", 
    //     total_connections, invalid_lines, total_lines - invalid_lines, invalid_datagrams);

    if (sendto(key->fd, "PERF!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		log(DEBUG, "%s", "Error sending response");
}
