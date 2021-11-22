// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <main.h>

proxy_configuration_ptr proxy_config;
static bool done = false;
int server_4 = -1;
int server_6 = -1;

int admin_4 = -1;
int admin_6 = -1;

float client_timeout = 120.0;

static void sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

int main(int argc, char *argv[]) {
    int ret = 0;

    proxy_config = parse_options(argc, argv);
    close(STDIN);
    
    const char *error_message   = NULL;
    selector_status status      = SELECTOR_SUCCESS;
    fd_selector selector        = NULL;

    if(proxy_config->pop3_listen_address == NULL){
        server_6 = setup_server_socket("::", proxy_config->pop3_listen_port, IPPROTO_TCP, false);
        server_4 = setup_server_socket("0.0.0.0", proxy_config->pop3_listen_port, IPPROTO_TCP, true);
    } else if (is_ipv6(proxy_config->pop3_listen_address)){
        server_6 = setup_server_socket(proxy_config->pop3_listen_address, proxy_config->pop3_listen_port, IPPROTO_TCP, false);
    } else {
        server_4 = setup_server_socket(proxy_config->pop3_listen_address, proxy_config->pop3_listen_port, IPPROTO_TCP, true);
    }

    if(server_4 == -1 && server_6 == -1)
        goto finally; //TODO que pasa si tenia que escuchar en las dos si o si?

    log(INFO, "Listening on TCP port %d", proxy_config->pop3_listen_port);
    
    if(proxy_config->admin_listen_address == NULL){
        admin_4 = setup_server_socket("127.0.0.1", proxy_config->admin_listen_port, IPPROTO_UDP, true); //TODO pasarlos a define
        admin_6 = setup_server_socket("::1", proxy_config->admin_listen_port, IPPROTO_UDP, false);
    } else if (is_ipv6(proxy_config->admin_listen_address)){
        admin_6 = setup_server_socket(proxy_config->admin_listen_address, proxy_config->admin_listen_port, IPPROTO_UDP, false);
    } else {
        admin_4 = setup_server_socket(proxy_config->admin_listen_address, proxy_config->admin_listen_port, IPPROTO_UDP, true);
    }

    if(admin_4 == -1 && admin_6 == -1)
        goto finally; //TODO que pasa si tenia que escuchar en las dos si o si?

    init_parser_defs();

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if((server_4 != -1 && selector_fd_set_nio(server_4) == -1) || 
        (server_6 != -1 && selector_fd_set_nio(server_6) == -1) ||
        (admin_4 != -1 && selector_fd_set_nio(admin_4) == -1) ||
        (admin_6 != -1 && selector_fd_set_nio(admin_6) == -1)) {
            
        error_message = "Failed setting socket as non-blocking";
        goto finally;
    }
        
    const struct selector_init conf = {
            .signal = SIGALRM,
            .select_timeout = {
                    .tv_sec  = 20,
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
            .handle_read    = pop3_passive_accept,
    };

    const struct fd_handler admin_handler = {
            .handle_read    = admin_parse,
    };

    if (server_4 != -1) {
        status = selector_register(selector, server_4, &pop3_handler, OP_READ, NULL);
        if(status != SELECTOR_SUCCESS) {
            error_message = "Failed registering server fd";
            goto finally;
        }
    }
    if (server_6 != -1) {
        status = selector_register(selector, server_6, &pop3_handler, OP_READ, NULL);
        if(status != SELECTOR_SUCCESS) {
            error_message = "Failed registering server fd";
            goto finally;
        }
    }
    
    if (admin_4 != -1) {
        status = selector_register(selector, admin_4, &admin_handler, OP_READ, NULL);
        if(status != SELECTOR_SUCCESS) {
            error_message = "Failed registering admin fd";
            goto finally;
        }
    }

    if (admin_6 != -1) {
        status = selector_register(selector, admin_6, &admin_handler, OP_READ, NULL);
        if(status != SELECTOR_SUCCESS) {
            error_message = "Failed registering admin fd";
            goto finally;
        }
    }
    
    struct sigaction sa;
    sa.sa_handler = SIG_DFL; //handle signal by ignoring
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &sa, 0) == -1) {
        perror(0);
        error_message = "Failed to execute sigignore";
        goto finally;
    }

    time_t last_activity = time(NULL);

    while(!done) {
        error_message = NULL;
        status = selector_select(selector);
        time_t current_activity = time(NULL);
        if(difftime(current_activity, last_activity) >= client_timeout/4) {
            last_activity = current_activity;
            selector_notify_timeout(selector); // Hacemos trigger del handle_timeout
        }

        if(status != SELECTOR_SUCCESS) {
            error_message = "Serving";
            goto finally;
        }
    }
    if(error_message == NULL) {
        error_message = "Closing...";
    }


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
    pop3_pool_destroy();
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();
    if(server_4 >= 0) {
        close(server_4);
    }
    if(server_6 >= 0) {
        close(server_6);
    }
    if(admin_4 >= 0) {
        close(admin_4);
    }
    if(admin_6 >= 0) {
        close(admin_6);
    }
    return ret;
}