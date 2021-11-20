#include <server_utils.h>


int setup_server_socket(char * listen_addr, int service, unsigned protocol, bool is_ipv4) {
	char srvc[6] = {0};

	if (sprintf(srvc, "%d", service) < 0) {
		log(FATAL, "%s", "invalid port");
		return -1;
	}

	struct addrinfo address_criteria;
	memset(&address_criteria, 0, sizeof(address_criteria));
	address_criteria.ai_family = AF_INET6;
	address_criteria.ai_flags = AI_PASSIVE;

    if (is_ipv4) {
        log(DEBUG, "%s", "is ipv4");
        address_criteria.ai_family = AF_INET;
    }
    
	if (protocol == IPPROTO_TCP) {
		address_criteria.ai_socktype = SOCK_STREAM;
		address_criteria.ai_protocol = IPPROTO_TCP;
	} else {
		address_criteria.ai_socktype = SOCK_DGRAM;
		address_criteria.ai_protocol = IPPROTO_UDP;
	}

	struct addrinfo* server_address;
	int rtnVal = getaddrinfo(listen_addr, srvc, &address_criteria, &server_address);
	if (rtnVal != 0) {
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		return -1;
	}

	int server_sock = -1;
	for (struct addrinfo* addr = server_address; addr != NULL && server_sock == -1; addr = addr->ai_next) {
		errno = 0;
		server_sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (server_sock < 0) 
			continue; 

		int yes = 1;
		if (!is_ipv4 && setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&yes, sizeof(yes)) < 0) {
			log(ERROR, "%s", "Set socket options failed");
            close(server_sock);
            server_sock = -1;
			continue;
		}

        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            log(ERROR, "%s", "Set socket options failed");
            close(server_sock);
            server_sock = -1;
            continue;
        }

		int can_bind = false;
		if (bind(server_sock, addr->ai_addr, addr->ai_addrlen) == 0) {
			can_bind = true;
			if ((protocol == IPPROTO_TCP) && (listen(server_sock, MAX_PENDING) != 0)) {
				can_bind = false;
			}
		}

		if (!can_bind) {
			log(DEBUG, "Unable to bind %s", strerror(errno));
			close(server_sock);
			server_sock = -1;
		}
	}

    log(INFO, "socket %d", server_sock);
    
	freeaddrinfo(server_address);

	return server_sock;
}
