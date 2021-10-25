#include "include/pop3nio.h"

static const unsigned  max_pool  = 50;
static unsigned        pool_size = 0;
static struct pop3     *pool     = NULL;

enum pop3_state {
    /*
     * Solves origin name server
     * Interests:
     *      - OP_READ   over client_fd
     * Transitions:
     *      - CONNECT   when the name is resolved
     *      - ERROR     if getaddrinfo fails
     */
    RESOLVE_ORIGIN,

    /*
     * Connects to origin server
     * Interests:
     *      - None
     * Transitions:
     *      - HELLO     when the connection is established
     *      - ERROR     if connection failed
     */
    CONNECT,

    /*
     * Reads the hello message from the origin server
     * Interests:
     *      - OP_WRITE  over client_fd
     * Transitions:
     *      - HELLO     while the message is not complete
     *      - CAPA      when the message is complete
     *      - ERROR     if connection failed
     */
    HELLO,

    /*
     * Asks supporting features to origin server (does it support pipelining?)
     * Interests:
     *      - OP_READ over origin_fd
     * Transitions:
     *      - CAPA      while the message is not complete
     *      - REQUEST   when the message is complete
     *      - ERROR     if connection failed
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
    *       - ERROR     if there's any error
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
    *       - ERROR     if there's any error
    */
    RESPONSE,

    /*
    * Transforms an email with an external application
    * Interests:
    *       - 
    * Transitions:
    *       - TRANSFORM     while the transformation is not complete
    *       - REQUEST       when the transformation is complete
    *       - ERROR         if there's any error
    */
    TRANSFORM,
    DONE,
    ERROR,
};


struct request_st {
    t_buffer              *rb, *wb;
    //struct request_parser   parser;
    uint8_t               method;
};

struct response_st {
    t_buffer              *rb, *wb;
    //struct response_parser   parser;
    uint8_t               method;
};

struct pop3 {

    int                     client_fd;
    struct sockaddr_storage client_address;
    socklen_t               client_address_len;

    struct addrinfo *       origin_resolution;
    struct sockaddr_storage origin_address;
    socklen_t               origin_address_len;
    int                     origin_domain;
    fd                      origin_fd;

    union {
        struct request_st   request;
    } client;

    union {
        struct response_st  response;
    } orig;

    struct state_machine    stm;
    unsigned                references;
    struct pop3 *           next;
};

static void
pop3_destroy_(struct pop3* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

static void
pop3_destroy(struct pop3 *s) {
    if(s == NULL) {
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                pop3_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
pop3_pool_destroy(void) {
    struct pop3 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

#define ATTACHMENT(key) ( (struct pop3 *)(key)->data)

static void             pop3_read   (struct selector_key *key);
static void             pop3_write  (struct selector_key *key);
static void             pop3_block  (struct selector_key *key);
static void             pop3_close  (struct selector_key *key);
static struct pop3 *    pop3_new    (int client_fd);

static const struct fd_handler pop3_handler = {
        .handle_read   = pop3_read,
        .handle_write  = pop3_write,
        .handle_close  = pop3_close,
        .handle_block  = pop3_block,
};


void *
blocking_resolve_origin(void *k) {
	struct selector_key *key = (struct selector_key *)k;
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    pthread_detach(pthread_self());
    struct addrinfo hints = {
            .ai_family    = AF_UNSPEC,    /* Allow IPv4 or IPv6 */
            .ai_socktype  = SOCK_STREAM,  /* Datagram socket */
            .ai_flags     = AI_PASSIVE,   /* For wildcard IP address */
            .ai_protocol  = 0,            /* Any protocol */
            .ai_canonname = NULL,
            .ai_addr      = NULL,
            .ai_next      = NULL,
    };

	char origin_port[7] = {0};
    if (snprintf(origin_port, sizeof(origin_port), "%hu", proxy_config->origin_server_port) < 0) {
        fprintf(stderr, "Error parseando puerto");
    }
    
    if(getaddrinfo(proxy_config->origin_server_address, origin_port,
        &hints, &pop3_ptr->origin_resolution) != 0) {
        fprintf(stderr,"Domain name resolution error\n");
    }
    selector_notify_block(key->s, key->fd);
    free(k);
    return NULL;
}

int
resolve_origin(struct selector_key *key) {
    pthread_t tid;
    struct selector_key *k = malloc(sizeof(*key));
    if(k == NULL) return ERROR;
    memcpy(k, key, sizeof(*k));
    if(pthread_create(&tid, 0, blocking_resolve_origin, k) == -1) {
        return ERROR;
    } else {
        selector_set_interest_key(key, OP_NOOP);
    }
	return RESOLVE_ORIGIN;
}

int
done_resolving_origin(struct selector_key * key) {
    fprintf(stdout, "Termine");
	return DONE;
}

static const struct state_definition handlers[] = {
    {
        .state          = RESOLVE_ORIGIN,
        .on_write_ready = resolve_origin,
        .on_block_ready = done_resolving_origin
    },
    {
        .state          = CONNECT,
    },
    {
        .state          = HELLO,
    },
    {
        .state          = CAPA,
    },
    {
        .state          = REQUEST,
    },
    {
        .state          = RESPONSE,
    },
    {
        .state          = TRANSFORM,
    },
    {
        .state          = DONE,
    },
    {
        .state          = ERROR,
    }

};

void
pop3_passive_accept(struct selector_key *key) {

    struct sockaddr_storage client_address;
    socklen_t               client_address_len  = sizeof(client_address);
    struct pop3             *state              = NULL;
    const fd client = accept(key->fd, (struct sockaddr*) &client_address, &client_address_len);
    if(client == -1 || selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    if( (state = pop3_new(client)) == NULL ) {
        goto fail;
    }
    memcpy(&state->client_address, &client_address, client_address_len);
    state->client_address_len = client_address_len;

    if(selector_register(key->s, client, &pop3_handler, OP_WRITE, state) != SELECTOR_SUCCESS) {
        goto fail;
    }

    return;

    fail:
    if(client != -1) {
        close(client);
    }
    pop3_destroy(state);
}


static struct pop3 *
pop3_new(int client_fd) {
    struct pop3 *pop3_ptr;
    if (pool == NULL) {
        pop3_ptr = malloc(sizeof(*pop3_ptr));
    } else {
        pop3_ptr       = pool;
        pool       = pool->next;
        pop3_ptr->next = 0;
    }
    memset(pop3_ptr, 0x00, sizeof(*pop3_ptr));
    pop3_ptr->origin_fd             = -1;
    pop3_ptr->client_fd             = client_fd;
    pop3_ptr->client_address_len    = sizeof(client_fd);
    pop3_ptr->stm.initial           = RESOLVE_ORIGIN;
    pop3_ptr->stm.max_state         = ERROR;
    pop3_ptr->stm.states            = handlers;
    stm_init(&pop3_ptr->stm);
    // TODO: Agregar r/w buffers
    pop3_ptr->references            = 1;
    return pop3_ptr;
}

static void
pop3_done(struct selector_key* key);

static void
pop3_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        pop3_done(key);
    }
}

static void
pop3_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        pop3_done(key);
    }
}

static void
pop3_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        pop3_done(key);
    }
}

static void
pop3_close(struct selector_key *key) {
    pop3_destroy(ATTACHMENT(key));
}

static void
pop3_done(struct selector_key* key) {
    const int fds[] = {
            ATTACHMENT(key)->client_fd,
            ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}
