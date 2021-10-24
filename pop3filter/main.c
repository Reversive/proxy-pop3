#include "include/main.h"

proxy_configuration_ptr proxy_conf;
static bool done = false;

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n", signal);
    done = true;
}

// TODO: Cambiar fprintf por logging
int main(int argc, char *argv[]) {
    unsigned port = 9090;
    proxy_conf = malloc(sizeof(struct proxy_configuration_t));
    parse_options(argc, argv, NULL, NULL, NULL, proxy_conf);
    close(STDIN);
    const char *error_message   = NULL;
    selector_status status      = SELECTOR_SUCCESS;
    fd_selector selector        = NULL;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port        = htons(port);
    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        error_message = "Unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", port);
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    if(bind(server, (struct sockaddr*) &address, sizeof(address)) < 0) {
        error_message = "Unable to bind socket";
        goto finally;
    }

    if(listen(server, QUEUE_SIZE) < 0) {
        error_message = "Unable to listen";
        goto finally;
    }

    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == ERROR) {
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
            .handle_read    = accept_pop3_connection,
            .handle_write   = NULL,
            .handle_close   = NULL,
    };

    status = selector_register(selector, server, &pop3_handler, OP_READ, NULL);

    if(status != SELECTOR_SUCCESS) {
        error_message = "Failed registering fd";
        goto finally;
    }

    for(;!done;) {
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
        if(selector != NULL) {
            selector_destroy(selector);
        }
        selector_close();
        if(server >= 0) {
            close(server);
        }
        return ret;
}