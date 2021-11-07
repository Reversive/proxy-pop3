#include "include/main.h"

proxy_configuration_ptr proxy_config;
static bool done = false;


static void sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int main(int argc, char *argv[]) {
    proxy_config = parse_options(argc, argv);
    close(STDIN);
    const char *error_message   = NULL;
    selector_status status      = SELECTOR_SUCCESS;
    fd_selector selector        = NULL;
    fprintf(stdout, "Listening on TCP port %d\n", proxy_config->pop3_listen_port);
    struct addrinfo address_criteria;
	memset(&address_criteria, 0, sizeof(address_criteria));
	address_criteria.ai_family = AF_INET6;
	address_criteria.ai_flags = AI_PASSIVE;
    address_criteria.ai_socktype = SOCK_STREAM;
    address_criteria.ai_protocol = IPPROTO_TCP;

	struct addrinfo* server_address;
    char listen_port[7] = { 0 };
    if (snprintf(listen_port, sizeof(listen_port), "%hu", proxy_config->pop3_listen_port) < 0) {
        fprintf(stderr, "Error parseando puerto");
        goto finally;
    }
	int rtnVal = getaddrinfo(NULL, listen_port, &address_criteria, &server_address);
	if (rtnVal != 0) {
		log(FATAL, "getaddrinfo() failed %s", gai_strerror(rtnVal));
		goto finally;
	}

    init_parser_defs();

	int server = -1;
	for (struct addrinfo* addr = server_address; addr != NULL && server == -1; addr = addr->ai_next) {
		errno = 0;
		server = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (server < 0) {
			continue; 
		}

		int no = 0;
		if (setsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&no, sizeof(no)) < 0) {
			//log(ERROR, "Set socket options failed");
			continue;
		}
        int yes = 1;
        if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
            //log(ERROR, "Set socket options failed");
            continue;
        }

		int can_bind = false;
		if (bind(server, addr->ai_addr, addr->ai_addrlen) == 0) {
			can_bind = true;
			if (listen(server, 5) != 0) {//TODO cambiar el maxpending
				can_bind = false;
			}
		}
		if (!can_bind) {
			log(DEBUG, "Cant't bind %s", strerror(errno));
			close(server);
			server = -1;
		}
	}
	freeaddrinfo(server_address);
    if(server == -1)
        goto finally;
    //codigo nuestro

    if(listen(server, QUEUE_SIZE) < 0) {
        error_message = "Unable to listen";
        goto finally;
    }

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == -1) {
        error_message = "Failed setting socket as non-blocking";
        goto finally;
    }
        
    const struct selector_init conf = {
            .signal = SIGALRM,
            .select_timeout = {
                    .tv_sec  = 10,
                    .tv_nsec = 0,
            },
    };

    if(selector_init(&conf) != SELECTOR_SUCCESS) {
        error_message = "Failed initializing selector";
        goto finally;
    }


    selector = selector_new(SELECTOR_ELEMENTS);
    if(selector == NULL) {
        error_message = "Unable to create selector";
        goto finally;
    }


    const struct fd_handler pop3_handler = {
            .handle_read    = pop3_passive_accept
    };

    status = selector_register(selector, server, &pop3_handler, OP_READ, NULL);

    if(status != SELECTOR_SUCCESS) {
        error_message = "Failed registering fd";
        goto finally;
    }


    while(!done) {
        error_message = NULL;
        status = selector_select(selector);
        if(status != SELECTOR_SUCCESS) {
            error_message = "Serving";
            goto finally;
        }
    }
    if(error_message == NULL) {
        error_message = "Closing...";
    }

    int ret = 0;

finally:
        if(status != SELECTOR_SUCCESS) {
            fprintf(stderr, "%s: %s\n", (error_message == NULL) ? "": error_message,
                                        status == SELECTOR_IO ? strerror(errno) : selector_error(status));
            ret = 2;
        } else if(error_message) {
            perror(error_message);
            ret = 1;
        }
        destroy_parser_defs();
        if(selector != NULL) {
            selector_destroy(selector);
        }
        selector_close();
        if(server >= 0) {
            close(server);
        }
        return ret;
}