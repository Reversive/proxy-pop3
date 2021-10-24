#include "include/pop3nio.h"

static const unsigned  max_pool  = 50;
static unsigned        pool_size = 0;
static struct pop3 *   pool      = 0;

enum pop3state {
    HELLO_READ,
    HELLO_WRITE,
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

    struct addrinfo *       origin_resolution;
    struct sockaddr_storage origin_address;
    socklen_t               origin_address_len;
    int                     origin_domain;
    int                     origin_fd;

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

void
pop3_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_address;
    socklen_t               client_address_len = sizeof(client_address);
    struct pop3             *state          = NULL;

    const int client = accept(key->fd, (struct sockaddr*) &client_address,
                              &client_address_len);
    if(client == -1) {
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        goto fail;
    }
    state = pop3_new(client);
    if(state == NULL) {
        goto fail;
    }
    memcpy(&state->client_address, &client_address, client_address_len);

    if(SELECTOR_SUCCESS != selector_register(key->s, client, &pop3_handler,
                                             OP_READ, state)) {
        goto fail;
    }
    return ;
    fail:
    if(client != -1) {
        close(client);
    }
    pop3_destroy(state);
}


static struct pop3 *
pop3_new(int client_fd) {
    struct pop3 * pop3;
    if (pool == NULL) {
        pop3 = malloc(sizeof(*pop3));
    } else {
        pop3       = pool;
        pool       = pool->next;
        pop3->next = 0;
    }
    return pop3;
}
static void
pop3_done(struct selector_key* key);

static void
pop3_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum pop3state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        pop3_done(key);
    }
}

static void
pop3_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum pop3state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        pop3_done(key);
    }
}

static void
pop3_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum pop3state st = stm_handler_block(stm, key);

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
