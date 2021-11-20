#include <pop3admin.h>

void to_lower_str(char* in_str) {
	for (int i = 0; in_str[i]; i++) {
		in_str[i] = tolower(in_str[i]);
	}
}

void admin_parse(struct selector_key* key) {
    log(DEBUG, "%s", "Incoming admin datagram");
    char buffer[BUFFSIZE];
	struct sockaddr_in6 client_address;
	int read_chars;
    unsigned int len = sizeof(client_address);

	read_chars = recvfrom(key->fd, buffer, BUFFSIZE, 0, (struct sockaddr*) &client_address, &len);
    if(read_chars < 0) {
        log(ERROR, "%s", "Error reading datagram");
        return;
    }
    
	if (buffer[read_chars - 1] == '\n') // Por si lo estan probando con netcat, en modo interactivo
		read_chars--;

	buffer[read_chars] = 0;
	log(DEBUG, "UDP received: %s", buffer);
	to_lower_str(buffer);

    //char buffer_out[BUFFSIZE] = { 0 };
	// sprintf(buffer_out, "Connections: %d\r\nIncorrect lines: %d\r\nCorrect lines: %d\r\nInvalid datagrams: %d\r\n", 
    //     total_connections, invalid_lines, total_lines - invalid_lines, invalid_datagrams);

    if (sendto(key->fd, "HOLA!\r\n", 7, 0, (const struct sockaddr *) &client_address, len) < 0)
		log(DEBUG, "%s", "Error sending response");

	
}
