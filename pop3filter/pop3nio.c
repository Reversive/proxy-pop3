#include "include/pop3nio.h"

#define ATTACHMENT(key) ( (struct pop3 *)(key)->data)
#define BUFFER_SIZE 1024
struct parser_definition *end_of_line_parser_def;
struct parser_definition *capa_parser_def;

static void             pop3_read(struct selector_key* key);
static void             pop3_write(struct selector_key* key);
static void             pop3_block(struct selector_key* key);
static void             pop3_close(struct selector_key* key);
static struct           pop3* pop3_new(int client_fd);
static void             pop3_destroy_(struct pop3* s);
static void             pop3_destroy(struct pop3* s);
void                    pop3_pool_destroy(void);
static int              write_error_message(struct selector_key *key);

static const unsigned   max_pool = 50;
static unsigned         pool_size = 0;
static struct           pop3* pool = NULL;

enum pop3_state {
    /*
     * Solves origin name server
     * Interests:
     *      - OP_READ   over client_fd
     * Transitions:
     *      - CONNECT   when the name is resolved
     *      - FAILURE   if getaddrinfo fails
     */
    RESOLVE_ORIGIN,

    /*
     * Connects to origin server
     * Interests:
     *      - None
     * Transitions:
     *      - HELLO     when the connection is established
     *      - FAILURE   if connection failed
     */
     CONNECT,

     /*
      * Reads the hello message from the origin server
      * Interests:
      *      - OP_WRITE  over client_fd
      * Transitions:
      *      - HELLO     while the message is not complete
      *      - CAPA      when the message is complete
      *      - FAILURE   if connection failed
      */
      HELLO,

      /*
       * Asks supporting features to origin server (does it support pipelining?)
       * Interests:
       *      - OP_READ over origin_fd
       * Transitions:
       *      - CAPA      while the message is not complete
       *      - REQUEST   when the message is complete
       *      - FAILURE   if connection failed
       */
       CAPA,

       /*
       * Reads requests from client and sends them to the origin server
       * Interests:
       *       - OP_READ over client_fd
       *       - OP_WRITE over origin_fd
       * Transitions:
       *       - REQUEST   while the request is not complete
       *       - RESPONSE  when the request is complete
       *       - FAILURE   if there's any FAILURE
       */
       REQUEST,

       /*
       * Reads the response from the origin server and sends them to the client
       * Interests:
       *       - OP_READ over origin_fd
       *       - OP_WRITE over client_fd
       * Transitions:
       *       - RESPONSE  while the response is not complete
       *       - REQUEST   when the response is complete and transformation is not enabled
       *       - TRANSFORM when the response is complete and transformation is enabled
       *       - FAILURE     if there's any FAILURE
       */
       RESPONSE,

       /*
       * Transforms an email with an external application
       * Interests:
       *       -
       * Transitions:
       *       - TRANSFORM     while the transformation is not complete
       *       - REQUEST       when the transformation is complete
       *       - FAILURE       if there's any FAILURE
       */
       TRANSFORM,
       DONE,
       FAILURE_WITH_MESSAGE,
       FAILURE
};

static const struct state_definition handlers[] = {
    {
        .state = RESOLVE_ORIGIN,
        .on_write_ready = resolve_origin,
        .on_block_ready = done_resolving_origin
    },
    {
        .state = CONNECT,
        .on_write_ready = connection,
    },
    {
        .state = HELLO,
        .on_read_ready  = read_hello,
        .on_write_ready = write_hello,
        .on_arrival     = hello_arrival,
        .on_departure   = hello_departure
    },
    {
        .state = CAPA,
    },
    {
        .state = REQUEST,
        .on_arrival     = request_arrival,
        .on_read_ready  = read_request,
        .on_write_ready = write_request,
        .on_departure   = request_departure
    },
    {
        .state = RESPONSE,
    },
    {
        .state = TRANSFORM,
    },
    {
        .state = DONE,
    },
    {
        .state = FAILURE_WITH_MESSAGE,
        .on_write_ready = write_error_message
    },
    {
        .state = FAILURE,
    }

};

struct request_st {
    struct parser*  capa_parser;
};

struct response_st {
    t_buffer* rb, * wb;
    //struct request_parser   parser;
};

struct message_packet {
    char    *message;
    size_t  length;
    size_t  bytes_sent;
};

struct hello_st {
    struct message_packet message;
    struct parser*        hello_parser;
};

struct pop3 {
    int                     client_fd;
    struct sockaddr_storage client_address;
    socklen_t               client_address_len;

    struct addrinfo*        origin_resolution;
    struct addrinfo*        current_res;
    struct message_packet   error_message;

    struct sockaddr_storage origin_address;
    socklen_t               origin_address_len;
    int                     origin_domain;
    fd                      origin_fd;

    union {
        struct request_st   request;
    } client;

    union {
        struct response_st  response;
        struct hello_st     hello_state;
    } orig;

    uint8_t read_buffer[BUFFER_SIZE];
    uint8_t write_buffer[BUFFER_SIZE];

    t_buffer client_to_origin;
    t_buffer origin_to_client;

    struct state_machine    stm;
    unsigned                references;
    struct pop3* next;
};

static const struct fd_handler pop3_handler = {
        .handle_read = pop3_read,
        .handle_write = pop3_write,
        .handle_close = pop3_close,
        .handle_block = pop3_block,
};

static int is_ipv6(const char* host) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, host, &(sa.sin6_addr));
}

static int is_ipv4(const char* host) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, host, &(sa.sin_addr));
}

int is_valid_ip(const char* host) {
    return is_ipv4(host) || is_ipv6(host);
}

static void* blocking_resolve_origin(void* k) {
    struct selector_key* key = (struct selector_key*)k;
    struct pop3* pop3_ptr = ATTACHMENT(key);
    pthread_detach(pthread_self());
    struct addrinfo hints = {
            .ai_family = AF_UNSPEC,    /* Allow IPv4 or IPv6 */
            .ai_socktype = SOCK_STREAM,  /* Datagram socket */
            .ai_flags = AI_PASSIVE,   /* For wildcard IP address */
            .ai_protocol = 0,            /* Any protocol */
            .ai_canonname = NULL,
            .ai_addr = NULL,
            .ai_next = NULL,
    };

    char origin_port[7] = { 0 };
    if (snprintf(origin_port, sizeof(origin_port), "%hu", proxy_config->origin_server_port) < 0) {
        fprintf(stderr, "Error parseando puerto");
    }

    if (getaddrinfo(proxy_config->origin_server_address, origin_port,
        &hints, &pop3_ptr->origin_resolution) != 0) {
        fprintf(stderr, "Domain name resolution error\n");
    }
    pop3_ptr->current_res = pop3_ptr->origin_resolution;
    selector_notify_block(key->s, key->fd);
    free(k);
    return NULL;
}

void send_error(int fd, const char* error) {
    send(fd, error, strlen(error), 0);
}

static int connect_to_origin_by_ip(struct selector_key *key, int family, void *sock_addr, socklen_t sock_addr_size ) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock >= 0) {
        errno = 0;
        if (selector_fd_set_nio(sock) == -1) {
            goto ip_connect_fail;   
        }
        int ret = connect(sock, (struct sockaddr *) sock_addr, sock_addr_size);
        if (ret == -1 && errno == EINPROGRESS) {
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || selector_register(key->s, sock, &pop3_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                goto ip_connect_fail;
            }
            return CONNECT;
        } else if(ret == 0) {
            pop3_ptr->origin_fd = sock;
            send_error(pop3_ptr->client_fd, "Welcome to the best POP3 server.");
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
                goto ip_connect_fail;     

            if (selector_register(key->s, sock, &pop3_handler, OP_READ, key->data) != SELECTOR_SUCCESS)
                goto ip_connect_fail;
                   
            return HELLO;
        } else {
            log(DEBUG, "%d", errno);
            goto ip_connect_fail;
        }
    }
ip_connect_fail:
    perror("Error: ");
    if(sock != -1)
        close(sock);

    return FAILURE_WITH_MESSAGE;
}

static int resolve_origin(struct selector_key* key) {
    pthread_t tid;
    struct selector_key* k = malloc(sizeof(*key));
    if (k == NULL)
        return FAILURE;

    if(is_ipv4(proxy_config->origin_server_address)) {
        struct sockaddr_in servaddr;
        fprintf(stderr, "%d", inet_pton(AF_INET, proxy_config->origin_server_address, &(servaddr.sin_addr)));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(proxy_config->origin_server_port);
        return connect_to_origin_by_ip(key, AF_INET, (void*)&servaddr, sizeof(servaddr));
    } else if (is_ipv6(proxy_config->origin_server_address)) {
        struct sockaddr_in6 servaddr;
        servaddr.sin6_family = AF_INET6;
        servaddr.sin6_port = htons(proxy_config->origin_server_port);
        inet_pton(AF_INET6, proxy_config->origin_server_address, &(servaddr.sin6_addr));
        return connect_to_origin_by_ip(key, AF_INET6, (void*)&servaddr, sizeof(servaddr));
    }
    memcpy(k, key, sizeof(*k));
    if (pthread_create(&tid, 0, blocking_resolve_origin, k) == -1) {
        return FAILURE;
    }
    else {
        selector_set_interest_key(key, OP_NOOP);
    }
    return RESOLVE_ORIGIN;
}

static int connect_to_origin(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    
    int sock = -1;
    while (pop3_ptr->current_res != NULL && sock == -1) {
        sock = socket(pop3_ptr->current_res->ai_family, pop3_ptr->current_res->ai_socktype, pop3_ptr->current_res->ai_protocol);
        if (sock >= 0) {
            errno = 0;
            if (selector_fd_set_nio(sock) == -1)
                goto connect_fail;

            if (connect(sock,  pop3_ptr->current_res->ai_addr, pop3_ptr->current_res->ai_addrlen) == -1 && errno == EINPROGRESS) {
                if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || selector_register(key->s, sock, &pop3_handler, OP_WRITE, key->data) != SELECTOR_SUCCESS) {
                    goto connect_fail;
                }
            } else {
                goto connect_fail;
            }
        } else {
connect_fail:
            close(sock);
            sock = -1;
            pop3_ptr->current_res = pop3_ptr->current_res->ai_next; 
        }
    }
    
    if(sock == -1) {
        freeaddrinfo(pop3_ptr->origin_resolution);
        pop3_ptr->error_message.message = "-ERR Connection refused.\r\n";
        if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;

        return FAILURE_WITH_MESSAGE;
    }
    return CONNECT;
}

static int done_resolving_origin(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    return pop3_ptr->origin_resolution == NULL ? FAILURE : connect_to_origin(key);
}



static int connection(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    int error;
    socklen_t len = sizeof(error);
    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
        selector_set_interest_key(key, OP_NOOP);
        pop3_ptr->current_res = pop3_ptr->current_res->ai_next;
        if(pop3_ptr->current_res == NULL) {
            pop3_ptr->error_message.message = "-ERR Connection refused.\r\n";
            if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
                return FAILURE;
            
            return FAILURE_WITH_MESSAGE;
        }
        return connect_to_origin(key);
    }
    if(pop3_ptr->origin_resolution != NULL) {
        freeaddrinfo(pop3_ptr->origin_resolution);
        pop3_ptr->origin_resolution = NULL;
    }
        
    pop3_ptr->origin_fd = key->fd;
    send_error(pop3_ptr->client_fd, "Welcome to the best POP3 server.");

    selector_set_interest_key(key, OP_READ);
    return HELLO;
}

void hello_arrival(struct selector_key* key){
    struct pop3* pop3_ptr = ATTACHMENT(key);
    end_of_line_parser_def = malloc(sizeof(struct parser_definition));
    struct parser_definition aux = parser_utils_strcmpi("\r\n");
    end_of_line_parser_def = &aux;
    pop3_ptr->orig.hello_state.hello_parser = parser_init(parser_no_classes(), end_of_line_parser_def);
}

void hello_departure(struct selector_key* key){
    struct pop3* pop3_ptr = ATTACHMENT(key);
    parser_destroy(pop3_ptr->orig.hello_state.hello_parser);
    free(end_of_line_parser_def);
}

static int read_hello(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);

    size_t max_size;
    uint8_t* ptr = buffer_write_ptr(&pop3_ptr->origin_to_client, &max_size);
    ssize_t read_chars = recv(pop3_ptr->origin_fd, ptr, max_size, 0);
    if (read_chars <= 0) {
        pop3_ptr->error_message.message = "Error reading from origin";
        if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }
    buffer_write_adv(&pop3_ptr->origin_to_client, read_chars);

    if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
        return FAILURE;

    return HELLO;
}

static int write_hello(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    
    size_t max_size;
    uint8_t* ptr = buffer_read_ptr(&pop3_ptr->origin_to_client, &max_size);

    ssize_t sent_bytes;
    if( (sent_bytes = send(key->fd, ptr, max_size, 0)) == -1) {
        pop3_ptr->error_message.message = "Error writing from origin";
        
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }
    
    buffer_read_adv(&pop3_ptr->origin_to_client, sent_bytes);

    if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || selector_set_interest(key->s, pop3_ptr->origin_fd, OP_READ) != SELECTOR_SUCCESS)
        return FAILURE;

    return HELLO;
}

static void request_arrival(struct selector_key* key) { //TODO ver de como tener esto ya creado
    struct pop3* pop3_ptr = ATTACHMENT(key);
    capa_parser_def = malloc(sizeof(struct parser_definition));
    //TODO agregar todos los comandos
    struct parser_definition aux = parser_utils_strcmpi("CAPA\r\n");
    capa_parser_def = &aux;
    pop3_ptr->client.request.capa_parser = parser_init(parser_no_classes(), capa_parser_def);
}

static void request_departure(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    parser_destroy(pop3_ptr->client.request.capa_parser);
    free(end_of_line_parser_def);
}

static int read_request(struct selector_key* key){
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    size_t max_size;
    uint8_t* ptr = buffer_write_ptr(&pop3_ptr->client_to_origin, &max_size);
    ssize_t read_chars = recv(pop3_ptr->client_fd, ptr, max_size, 0);
    if (read_chars <= 0) {
        pop3_ptr->error_message.message = "Error reading from client";
        if (selector_set_interest(key->s, pop3_ptr->origin_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }
    buffer_write_adv(&pop3_ptr->client_to_origin, read_chars);

    if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || selector_set_interest(key->s, pop3_ptr->origin_fd, OP_WRITE) != SELECTOR_SUCCESS)
        return FAILURE;

    return REQUEST;
    
}

static int write_request(struct selector_key* key){
    
}

static int write_error_message(struct selector_key *key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    if(pop3_ptr->error_message.message == NULL)
        return FAILURE;
    if(pop3_ptr->error_message.length == 0)
        pop3_ptr->error_message.length = strlen(pop3_ptr->error_message.message);
        
    char    *current_position = pop3_ptr->error_message.message + pop3_ptr->error_message.bytes_sent;
    ssize_t  diff = pop3_ptr->error_message.length - pop3_ptr->error_message.bytes_sent;
    ssize_t  bytes_sent = send(pop3_ptr->client_fd, current_position, diff, MSG_NOSIGNAL);
    if(bytes_sent == -1 || bytes_sent == diff) {
        return FAILURE;
    }
    
    pop3_ptr->error_message.bytes_sent += bytes_sent;
    return FAILURE_WITH_MESSAGE;
}

void pop3_passive_accept(struct selector_key* key) {
    struct sockaddr_storage client_address;
    socklen_t               client_address_len = sizeof(client_address);
    struct pop3* state = NULL;

    const fd client = accept(key->fd, (struct sockaddr*)&client_address, &client_address_len);

    if (client == -1 || selector_fd_set_nio(client) == -1)
        goto fail;

    if ((state = pop3_new(client)) == NULL)
        goto fail;

    memcpy(&state->client_address, &client_address, client_address_len);
    state->client_address_len = client_address_len;

    if (selector_register(key->s, client, &pop3_handler, OP_WRITE, state) != SELECTOR_SUCCESS) {
        goto fail;
    }

    return;

fail:
    if (client != -1) {
        close(client);
    }
    pop3_destroy(state);
}

//
//      POP3 METHODS
//


static struct pop3* pop3_new(int client_fd) {
    struct pop3* pop3_ptr;
    if (pool == NULL) {
        pop3_ptr = malloc(sizeof(*pop3_ptr));
    }
    else {
        pop3_ptr = pool;
        pool = pool->next;
        pop3_ptr->next = 0;
    }
    memset(pop3_ptr, 0x00, sizeof(*pop3_ptr));
    pop3_ptr->origin_fd = -1;
    pop3_ptr->client_fd = client_fd;
    pop3_ptr->client_address_len = sizeof(client_fd);
    pop3_ptr->stm.initial = RESOLVE_ORIGIN;
    pop3_ptr->stm.max_state = FAILURE;
    pop3_ptr->stm.states = handlers;
    stm_init(&pop3_ptr->stm);

    buffer_init(&pop3_ptr->client_to_origin, BUFFER_SIZE, pop3_ptr->read_buffer);
    buffer_init(&pop3_ptr->origin_to_client, BUFFER_SIZE, pop3_ptr->write_buffer);
    // TODO: Agregar r/w buffers
    pop3_ptr->references = 1;
    return pop3_ptr;
}

static void pop3_done(struct selector_key* key);

static void pop3_read(struct selector_key* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_read(stm, key);

    if (FAILURE == st || DONE == st) {
        pop3_done(key);
    }
}

static void pop3_write(struct selector_key* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_write(stm, key);

    if (FAILURE == st || DONE == st) {
        pop3_done(key);
    }
}

static void pop3_block(struct selector_key* key) {
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_block(stm, key);

    if (FAILURE == st || DONE == st) {
        pop3_done(key);
    }
}

static void pop3_close(struct selector_key* key) {
    pop3_destroy(ATTACHMENT(key));
}

static void pop3_done(struct selector_key* key) {
    const int fds[] = {
            ATTACHMENT(key)->client_fd,
            ATTACHMENT(key)->origin_fd,
    };
    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}

static void pop3_destroy_(struct pop3* s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

static void pop3_destroy(struct pop3* s) {
    if (s == NULL) {
    }
    else if (s->references == 1) {
        if (s != NULL) {
            if (pool_size < max_pool) {
                s->next = pool;
                pool = s;
                pool_size++;
            }
            else {
                pop3_destroy_(s);
            }
        }
    }
    else {
        s->references -= 1;
    }
}

void pop3_pool_destroy(void) {
    struct pop3* next, * s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        free(s);
    }
}

