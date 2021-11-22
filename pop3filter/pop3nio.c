// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <pop3nio.h>

#define ATTACHMENT(key) ( (struct pop3 *)(key)->data)
#define BUFFER_SIZE 1024
#define COMMANDS 12
#define R 0
#define W 1
#define END_STRING ".\r\n"

typedef struct parser* ptr_parser;

struct parser_definition *end_of_line_parser_def;
struct parser_definition *end_of_multiline_parser_def;
struct parser_definition *pipelining_parser_def;
struct parser_definition *dot_parser_def;

static void             pop3_done(struct selector_key* key);
static void             pop3_read(struct selector_key* key);
static void             pop3_write(struct selector_key* key);
static void             pop3_block(struct selector_key* key);
static void             pop3_close(struct selector_key* key);
static void             pop3_timeout(struct selector_key* key);
static void             update_last_activity(struct selector_key* key);
static struct pop3*     pop3_new(int client_fd);
static void             pop3_destroy_(struct pop3* s);
static void             pop3_destroy(struct pop3* s);
static int              write_error_message(struct selector_key *key);
static int              resolve_origin(struct selector_key* key);
static int              done_resolving_origin(struct selector_key* key);
static int              connection(struct selector_key* key);
static int              hello_read(struct selector_key* key);
static int              hello_write(struct selector_key* key);
static int              request_read(struct selector_key* key);
static int              request_write(struct selector_key* key);
static int              write_error_message(struct selector_key* key);
static int              capa_read(struct selector_key* key);
static void             hello_departure(struct selector_key *key);
static int              response_write(struct selector_key* key);
static int              response_read(struct selector_key* key);
static int              transform_read(struct selector_key* key);
static int              transform_write(struct selector_key* key);
static int              transform_init(struct selector_key* key);
static int              transform_failure(struct selector_key* key);

static const unsigned   max_pool = 50;
static unsigned         pool_size = 0;
static struct           pop3* pool = NULL;

//Metricas
size_t historic_connections = 0;
size_t current_connections = 0;
size_t transferred_bytes = 0;

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
       * Adds pipelining to CAPA origin response if needed
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
       TRANSFORM_FAILURE,
       DONE,
       FAILURE_WITH_MESSAGE, // TODO chequeo de estas funciones
       FAILURE
};

enum current_command {CMD_CAPA = 0, CMD_USER, CMD_PASS, CMD_LIST, CMD_RETR, CMD_DELE, CMD_TOP, CMD_UIDL, CMD_NOOP, CMD_QUIT, CMD_RSET, CMD_STAT};

static const struct state_definition handlers[] = {
    {
        .state          = RESOLVE_ORIGIN,
        .on_write_ready = resolve_origin,
        .on_block_ready = done_resolving_origin
    },
    {
        .state          = CONNECT,
        .on_write_ready = connection,
    },
    {
        .state          = HELLO,
        .on_read_ready  = hello_read,
        .on_write_ready = hello_write,
        .on_departure   = hello_departure
    },
    {
        .state          = CAPA,
        .on_read_ready  = capa_read,
    },
    {
        .state          = REQUEST,
        .on_read_ready  = request_read,
        .on_write_ready = request_write
    },
    {
        .state          = RESPONSE,
        .on_read_ready  = response_read,
        .on_write_ready = response_write
    },
    {
        .state          = TRANSFORM,
        .on_read_ready  = transform_read,
        .on_write_ready = transform_write
    },
    {
        .state          = TRANSFORM_FAILURE,
        .on_write_ready = transform_failure,
    },
    {
        .state          = DONE,
    },
    {
        .state          = FAILURE_WITH_MESSAGE,
        .on_write_ready = write_error_message
    },
    {
        .state          = FAILURE,
    }

};

struct request_st {
    int         parser_states[COMMANDS];
    ptr_parser  end_of_line_parser;
};

struct response_st {
    ptr_parser      end_of_line_parser;
    bool            is_positive_response;
    bool            has_args;
    bool            is_done;
    t_buffer_ptr    write_buffer;
    int             write_fd;
    int             read_fd;
    int             current_command;
    char*           end_string;
    size_t          end_string_len;
};

struct message_packet {
    char    *message;
    size_t  length;
    size_t  bytes_sent;
};

struct hello_st {
    ptr_parser          hello_parser;
};

struct capa_st {
    ptr_parser          end_of_multiline_parser;
    ptr_parser          pipelining_parser;
    bool                supports_pipelining;
    bool                has_started;
    bool                has_dot;
};

struct transform_st {
    int     write_fd;
    int     read_fd;
    bool    started_reading;
    bool    skipped_line;
    bool    is_done;
    bool    was_dot;

    t_buffer pipe_to_proxy;
    t_buffer proxy_to_pipe;
    ptr_parser  dot_parser;
    ptr_parser  end_parser;
    bool    found_end;
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
    int                     current_command;
    bool                    may_multi;
    bool                    has_args;
    bool                    may_have_args;
    ptr_parser              parsers[COMMANDS];

    command_queue           commands_left;
    ssize_t                 unmatched_len;

    struct request_st       request;

    struct capa_st          capa;
    struct response_st      response;
    struct hello_st         hello_state;
    time_t                  last_activity;
    
    bool                    checked_user;
    uint8_t                 user[40];
    bool                    has_valid_user;


    struct transform_st     transform;

    enum pop3_state         current_return;

    uint8_t                 read_buffer[BUFFER_SIZE];
    uint8_t                 write_buffer[BUFFER_SIZE];
    uint8_t                 proxy_to_pipe_buffer[BUFFER_SIZE];
    uint8_t                 pipe_to_proxy_buffer[BUFFER_SIZE];


    t_buffer                client_to_origin;
    t_buffer                origin_to_client;
    t_buffer                transform_buffer;

    struct state_machine    stm;
    unsigned                references;
    struct pop3*            next;
};

static const struct fd_handler pop3_handler = {
        .handle_read    = pop3_read,
        .handle_write   = pop3_write,
        .handle_close   = pop3_close,
        .handle_block   = pop3_block,
        .handle_timeout = pop3_timeout
};

typedef struct t_command {
    char * name;
    bool(*is_multi)(struct pop3 * pop3_ptr);
    enum pop3_state response_state;
} t_command;

static bool multi_true(struct pop3 * pop3_ptr) {
    return true;
}

static bool multi_false(struct pop3 * pop3_ptr) {
    return false;
}

static bool multi_no_arguments(struct pop3 * pop3_ptr) {
    return !(pop3_ptr->response.has_args);
}

static bool multi_arguments(struct pop3 * pop3_ptr) {
    return pop3_ptr->response.has_args;
}

t_command command_list[] = {{"CAPA", multi_true, CAPA}, {"USER ", multi_false, RESPONSE}, {"PASS", multi_false, RESPONSE}, {"LIST", multi_no_arguments, RESPONSE}, 
    {"RETR", multi_arguments, RESPONSE}, {"DELE", multi_false, RESPONSE}, {"TOP", multi_arguments, RESPONSE}, {"UIDL", multi_no_arguments, RESPONSE}, 
    {"NOOP", multi_false, RESPONSE}, {"QUIT", multi_false, RESPONSE}, {"RSET", multi_false, RESPONSE}, {"STAT", multi_false, RESPONSE}};

struct parser_definition *defs[COMMANDS];


void init_parser_defs() {
    for (int i = 0; i < COMMANDS; i++) {
        defs[i] = malloc(sizeof(struct parser_definition));
        struct parser_definition aux = parser_utils_strcmpi(command_list[i].name);
        memcpy(defs[i], &aux, sizeof(struct parser_definition));
    }

    end_of_line_parser_def = malloc(sizeof(struct parser_definition));
    struct parser_definition end_of_line_parser_aux = parser_utils_strcmpi("\r\n");
    memcpy(end_of_line_parser_def, &end_of_line_parser_aux, sizeof(struct parser_definition));   

    end_of_multiline_parser_def = malloc(sizeof(struct parser_definition));
    struct parser_definition end_of_multiline_parser_aux = parser_utils_strcmpi("\r\n.\r\n");
    memcpy(end_of_multiline_parser_def, &end_of_multiline_parser_aux, sizeof(struct parser_definition));    

    pipelining_parser_def = malloc(sizeof(struct parser_definition));
    struct parser_definition pipelining_parser_aux = parser_utils_strcmpi("\r\nPIPELINING\r\n");
    memcpy(pipelining_parser_def, &pipelining_parser_aux, sizeof(struct parser_definition));

    dot_parser_def = malloc(sizeof(struct parser_definition));
    struct parser_definition dot_parser_aux = parser_utils_strcmpi("\r\n.");
    memcpy(dot_parser_def, &dot_parser_aux, sizeof(struct parser_definition));
}

void destroy_parser_defs() {
    for (int i = 0; i < COMMANDS; i++) {
        parser_utils_strcmpi_destroy(defs[i]);
        free(defs[i]);
    }

    parser_utils_strcmpi_destroy(end_of_line_parser_def);
    parser_utils_strcmpi_destroy(end_of_multiline_parser_def);
    parser_utils_strcmpi_destroy(pipelining_parser_def);
    parser_utils_strcmpi_destroy(dot_parser_def);
        
    free(end_of_line_parser_def);
    free(end_of_multiline_parser_def);
    free(pipelining_parser_def);
    free(dot_parser_def);
}

void init_parsers(struct pop3* pop3_ptr) {
    log(DEBUG, "%s", "Initializing parsers");
    pop3_ptr->hello_state.hello_parser = parser_init(parser_no_classes(), end_of_line_parser_def);
    pop3_ptr->request.end_of_line_parser = parser_init(parser_no_classes(), end_of_line_parser_def);
    pop3_ptr->response.end_of_line_parser = NULL;
    pop3_ptr->capa.end_of_multiline_parser = NULL;
    pop3_ptr->transform.dot_parser = NULL;
    pop3_ptr->transform.end_parser = NULL;
    pop3_ptr->capa.pipelining_parser = NULL;

    for (int i = 0; i < COMMANDS; i++) {
        pop3_ptr->parsers[i] = parser_init(parser_no_classes(), defs[i]);
    }
}

static void reset_parsers(struct pop3* pop3_ptr) {
    for (int i = 0; i < COMMANDS; i++) {
        parser_reset(pop3_ptr->parsers[i]);
        pop3_ptr->request.parser_states[i] = 1;
    }
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

    pop3_ptr->current_res = NULL; 

    char origin_port[7] = { 0 };
    if (snprintf(origin_port, sizeof(origin_port), "%hu", proxy_config->origin_server_port) < 0) {
        log(ERROR, "%s %hu", "Could not parse port", proxy_config->origin_server_port);
        goto finally;
    }

    if (getaddrinfo(proxy_config->origin_server_address, origin_port,
        &hints, &pop3_ptr->origin_resolution) != 0) {
        log(ERROR, "%s %s:%s", "Domain name resolution error for domain", proxy_config->origin_server_address, origin_port);
        goto finally;
    }
    
    pop3_ptr->current_res = pop3_ptr->origin_resolution;
    
finally:
    selector_notify_block(key->s, key->fd);
    free(k);
    return NULL;
}

void send_error(int fd, const char* error) {
    send(fd, error, strlen(error), MSG_NOSIGNAL);
}


static int connect_to_origin_by_ip(struct selector_key *key, int family, void *sock_addr, socklen_t sock_addr_size ) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    char buff[SOCKADDR_TO_HUMAN_MIN];

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

            pop3_ptr->references++;

            return CONNECT;
        } else if(ret == 0) {
            pop3_ptr->origin_fd = sock;
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS ||
                selector_register(key->s, sock, &pop3_handler, OP_READ, key->data) != SELECTOR_SUCCESS){

                goto ip_connect_fail;
            }

            pop3_ptr->references++;

            log(INFO, "Client %s connected to origin %s", 
                sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) &pop3_ptr->client_address),
                sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) sock_addr));
  
            return HELLO;
        }
    }
ip_connect_fail:
    log(ERROR, "Client %s could not connect to origin %s:%hu",
        sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) &pop3_ptr->client_address),
        proxy_config->origin_server_address, proxy_config->origin_server_port);
    if(sock != -1)
        close(sock);

    return FAILURE_WITH_MESSAGE;
}

static int resolve_origin(struct selector_key* key) {
    if(is_ipv4(proxy_config->origin_server_address)) {
        struct sockaddr_in servaddr;
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(proxy_config->origin_server_port);
        inet_pton(AF_INET, proxy_config->origin_server_address, &(servaddr.sin_addr));
        return connect_to_origin_by_ip(key, AF_INET, (void*)&servaddr, sizeof(servaddr));
    } else if (is_ipv6(proxy_config->origin_server_address)) {
        struct sockaddr_in6 servaddr;
        servaddr.sin6_family = AF_INET6;
        servaddr.sin6_port = htons(proxy_config->origin_server_port);
        inet_pton(AF_INET6, proxy_config->origin_server_address, &(servaddr.sin6_addr));
        return connect_to_origin_by_ip(key, AF_INET6, (void*)&servaddr, sizeof(servaddr));
    }

    pthread_t tid;
    struct selector_key* k = malloc(sizeof(*key));
    if (k == NULL)
        return FAILURE;
        
    memcpy(k, key, sizeof(*k));
    if (pthread_create(&tid, 0, blocking_resolve_origin, k) == -1 || selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS){
        return FAILURE_WITH_MESSAGE; // TODO mensaje para el cliente
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
                pop3_ptr->references++;
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
    
        char buff[SOCKADDR_TO_HUMAN_MIN];
        log(ERROR, "Client %s could not connect to origin %s:%hu",
            sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) &pop3_ptr->client_address),
            proxy_config->origin_server_address, proxy_config->origin_server_port);
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
    int error = 0;
    socklen_t len = sizeof(error);

    char buff[SOCKADDR_TO_HUMAN_MIN]; // TODO podria ser una funcion print_connection

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
            return FAILURE;

        if(pop3_ptr->current_res != NULL)
            pop3_ptr->current_res = pop3_ptr->current_res->ai_next;

        if(pop3_ptr->current_res == NULL) {
            pop3_ptr->error_message.message = "-ERR Connection refused.\r\n";

            log(ERROR, "Client %s could not connect to origin %s:%hu",
                sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) &pop3_ptr->client_address),
                proxy_config->origin_server_address, proxy_config->origin_server_port);
                
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

    historic_connections++;
    
    pop3_ptr->origin_fd = key->fd;
    if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS)
        return FAILURE;
    
    log(INFO, "Client %s connected to origin %s:%hu",
        sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) &pop3_ptr->client_address),
        proxy_config->origin_server_address, proxy_config->origin_server_port);

    return HELLO;
}

static void hello_departure(struct selector_key *key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    pop3_ptr->current_command = -1;
    for (int i = 0; i < COMMANDS; i++)
         pop3_ptr->request.parser_states[i] = 1;
    
    pop3_ptr->may_multi = true;
    pop3_ptr->response.end_of_line_parser = NULL;
    pop3_ptr->response.is_done = false;
    pop3_ptr->checked_user = false;
    pop3_ptr->has_valid_user = false;
    pop3_ptr->may_have_args = false;

    if(proxy_config->pop3_filter_command != NULL) {
        buffer_init(&pop3_ptr->transform.proxy_to_pipe, BUFFER_SIZE, pop3_ptr->proxy_to_pipe_buffer);
        buffer_init(&pop3_ptr->transform.pipe_to_proxy, BUFFER_SIZE, pop3_ptr->pipe_to_proxy_buffer);
    }
}

static int hello_read(struct selector_key* key) {
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

    for(int i = 0; i < read_chars; i++) {
        const struct parser_event* state = parser_feed(pop3_ptr->hello_state.hello_parser, ptr[i]);
        if(state->type == STRING_CMP_EQ) {
            if(selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS
            || selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
                return FAILURE;
        } else if(state->type == STRING_CMP_NEQ) {
            parser_reset(pop3_ptr->hello_state.hello_parser);
        }
    }
    
    buffer_write_adv(&pop3_ptr->origin_to_client, read_chars);
    return HELLO;
}

static int hello_write(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);

    size_t max_size;
    uint8_t* ptr = buffer_read_ptr(&pop3_ptr->origin_to_client, &max_size);

    ssize_t sent_bytes;
    if( (sent_bytes = send(key->fd, ptr, max_size, MSG_NOSIGNAL)) == -1) {
        pop3_ptr->error_message.message = "Error writing from origin";
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }
    buffer_read_adv(&pop3_ptr->origin_to_client, sent_bytes);

    transferred_bytes += sent_bytes;

    if(buffer_pending_read(&pop3_ptr->origin_to_client) == 0) {
        if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS 
            || selector_set_interest(key->s, pop3_ptr->origin_fd, OP_NOOP) != SELECTOR_SUCCESS){
            
            return FAILURE;
        }
        return REQUEST;
    }
    return HELLO;
}


static int request_read(struct selector_key* key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    size_t max_size;
    uint8_t* ptr = buffer_write_ptr(&pop3_ptr->client_to_origin, &max_size);
    
    ssize_t read_chars = recv(pop3_ptr->client_fd, ptr, max_size, 0);

    if (read_chars < 0) {
        pop3_ptr->error_message.message = "Error reading from client";
        if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    } else if (read_chars == 0) {
        char buff[SOCKADDR_TO_HUMAN_MIN];
        log(INFO, "Client %s disconnected",
            sockaddr_to_human(buff, SOCKADDR_TO_HUMAN_MIN, (struct sockaddr *) &pop3_ptr->client_address));

        return DONE;
    }

    int last_command_end = 0;
    for(int i = 0; i < read_chars; i++) {
        const struct parser_event* end_of_line_state = parser_feed(pop3_ptr->request.end_of_line_parser, ptr[i]);
        
        if (end_of_line_state->type == STRING_CMP_EQ) {
            command_node node = calloc(1, sizeof(t_node));

            if(node == NULL) {
                pop3_ptr->error_message.message = "-ERR Error allocating memory";//TODO otro mensaje
                if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
                    return FAILURE;
                
                return FAILURE_WITH_MESSAGE;
            }
            node->command = pop3_ptr->current_command;
            node->command_len = i + 1 - last_command_end + pop3_ptr->unmatched_len;
            node->has_args = pop3_ptr->has_args;
            
            enqueue(pop3_ptr->commands_left, node);

            pop3_ptr->has_args = false;
            pop3_ptr->may_have_args = false;
            last_command_end = i + 1;

            reset_parsers(pop3_ptr);
            pop3_ptr->unmatched_len = 0;
            pop3_ptr->current_command = -1;
            parser_reset(pop3_ptr->request.end_of_line_parser);
            continue;
        } else if (end_of_line_state->type == STRING_CMP_NEQ) {
            parser_reset(pop3_ptr->request.end_of_line_parser);
        }

        if (pop3_ptr->current_command == -1) {
            for (int command = 0; command < COMMANDS; command++) {
                if (pop3_ptr->request.parser_states[command]) {
                    const struct parser_event* curr_command_state = parser_feed(pop3_ptr->parsers[command], ptr[i]);
                    
                    if(curr_command_state->type == STRING_CMP_EQ) {
                        pop3_ptr->current_command = command;
                    } else if(curr_command_state->type == STRING_CMP_NEQ) {
                        pop3_ptr->request.parser_states[command] = 0;
                    } 
                }
            }
        } else if(ptr[i] == ' ') {
            pop3_ptr->may_have_args = true;
        } else if (pop3_ptr->may_have_args && ptr[i] != '\r') {
            pop3_ptr->has_args = true;
        }
    }

    pop3_ptr->unmatched_len += read_chars - last_command_end;
    
    buffer_write_adv(&pop3_ptr->client_to_origin, read_chars);

    if(!is_empty(pop3_ptr->commands_left)){
        if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || selector_set_interest(key->s, pop3_ptr->origin_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
    }
    
    return REQUEST;
}

static void find_user(struct pop3* pop3_ptr, uint8_t * command, uint8_t len){
    uint8_t index;
    for(index = 0; index < len; index++){
        if(command[index] == ' ')
            break;
    }

    memcpy(pop3_ptr->user, command + index + 1, len - index - 2);
    pop3_ptr->user[len - index - 2 - 1] = 0;
}

static int request_write(struct selector_key* key){
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    size_t max_size;
    uint8_t* ptr = buffer_read_ptr(&pop3_ptr->client_to_origin, &max_size);

    command_node node = peek(pop3_ptr->commands_left);

    if(node->command == CMD_USER && !pop3_ptr->has_valid_user && !pop3_ptr->checked_user) {
        find_user(pop3_ptr, ptr, node->command_len);
        pop3_ptr->checked_user = true;
    }

    ssize_t sent_bytes;
    if( (sent_bytes = send(key->fd, ptr, node->command_len, MSG_NOSIGNAL)) == -1) {
        pop3_ptr->error_message.message = "Error writing to origin"; // TODO cambiar estos por un #DEFINE
        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }
    
    buffer_read_adv(&pop3_ptr->client_to_origin, sent_bytes);

    transferred_bytes += sent_bytes;

    if (sent_bytes == node->command_len) {
        dequeue(pop3_ptr->commands_left);
        if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS || selector_set_interest(key->s, pop3_ptr->client_fd, OP_NOOP) != SELECTOR_SUCCESS){
            return FAILURE;
        }
        pop3_ptr->response.has_args = node->has_args;
        pop3_ptr->response.current_command = node->command;
        
        if(node->command == CMD_USER && pop3_ptr->checked_user) {
            pop3_ptr->checked_user = false;
        }

        free(node);

        return (pop3_ptr->response.current_command == -1) ? RESPONSE : command_list[pop3_ptr->response.current_command].response_state;
    }

    node->command_len -= sent_bytes;
    return REQUEST;
}

static int response_read(struct selector_key* key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);

    
    size_t max_size;
    uint8_t* ptr = buffer_write_ptr(&pop3_ptr->origin_to_client, &max_size);
    ssize_t read_chars = recv(pop3_ptr->origin_fd, ptr, max_size, 0);

    if (read_chars <= 0) {
        pop3_ptr->error_message.message = "Error reading from origin";
        if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }
    
    if (pop3_ptr->response.end_of_line_parser == NULL) {
        pop3_ptr->current_return = RESPONSE;
        pop3_ptr->response.write_fd = pop3_ptr->client_fd;
        pop3_ptr->response.read_fd = pop3_ptr->origin_fd;
        pop3_ptr->response.write_buffer = &pop3_ptr->origin_to_client;
        
        if (pop3_ptr->response.current_command != -1 && 
            command_list[pop3_ptr->response.current_command].is_multi(pop3_ptr) && ptr[0] == '+') {
            
            pop3_ptr->current_return = command_list[pop3_ptr->response.current_command].response_state;

            if(pop3_ptr->response.current_command == CMD_RETR && proxy_config->pop3_filter_command != NULL) {
                pop3_ptr->current_return = transform_init(key);
                
                pop3_ptr->response.write_fd = pop3_ptr->transform.write_fd;
                pop3_ptr->response.read_fd = pop3_ptr->transform.read_fd;
            }
                
            pop3_ptr->response.is_positive_response = true;    
            pop3_ptr->response.end_of_line_parser = parser_init(parser_no_classes(), end_of_multiline_parser_def);
        } else {
            if (pop3_ptr->response.current_command == CMD_PASS && ptr[0] == '+')
                pop3_ptr->has_valid_user = true;
            
            pop3_ptr->response.end_of_line_parser = parser_init(parser_no_classes(), end_of_line_parser_def);
            pop3_ptr->response.is_positive_response = false;    
        }
    }

    for(int i = 0; i < read_chars; i++) {
        const struct parser_event* end_state = parser_feed(pop3_ptr->response.end_of_line_parser, ptr[i]);
      
        if(end_state->type == STRING_CMP_EQ) {
            pop3_ptr->response.is_done = true;
            pop3_ptr->response.end_string_len = 0;
            pop3_ptr->response.end_string = NULL;

            parser_destroy(pop3_ptr->response.end_of_line_parser);
            pop3_ptr->response.end_of_line_parser = NULL;
            break;
        } else if(end_state->type == STRING_CMP_NEQ) {
            parser_reset(pop3_ptr->response.end_of_line_parser);
            if (ptr[i] == '\r')
                parser_feed(pop3_ptr->response.end_of_line_parser, '\r');
        }
    }

    buffer_write_adv(&pop3_ptr->origin_to_client, read_chars);
        
    if(pop3_ptr->response.is_done || !buffer_can_write(&pop3_ptr->origin_to_client)) {
        if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || 
            selector_set_interest(key->s, pop3_ptr->response.write_fd, OP_WRITE) != SELECTOR_SUCCESS || 
            (pop3_ptr->response.read_fd != pop3_ptr->origin_fd && 
                selector_set_interest(key->s, pop3_ptr->response.read_fd, OP_READ) != SELECTOR_SUCCESS))
            return FAILURE;
    
        return pop3_ptr->current_return;
    }    
    
    return RESPONSE;
}

static int response_write(struct selector_key* key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    size_t max_size;    

    uint8_t* ptr = buffer_read_ptr(pop3_ptr->response.write_buffer, &max_size);
    ssize_t sent_bytes;
    if( (sent_bytes = send(key->fd, ptr, max_size, MSG_NOSIGNAL)) == -1) {
        pop3_ptr->error_message.message = "Error writing to client";

        if (selector_set_interest_key(key, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }

    transferred_bytes += sent_bytes;

    buffer_read_adv(pop3_ptr->response.write_buffer, sent_bytes);
    if (buffer_can_read(pop3_ptr->response.write_buffer)) // el buffer estará compactado, se puede escribir
        return RESPONSE;

    if(!pop3_ptr->response.is_done) {
        if(selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS ||
            selector_set_interest(key->s, pop3_ptr->response.read_fd, OP_READ) != SELECTOR_SUCCESS ||
            (pop3_ptr->response.write_fd != -1 && 
                pop3_ptr->response.write_fd != pop3_ptr->client_fd && 
                selector_set_interest(key->s, pop3_ptr->response.write_fd, OP_WRITE) != SELECTOR_SUCCESS))
            return FAILURE;
        
        //TODO arreglar esto para caso NO TRANSFORM
        return pop3_ptr->current_return;
    }

    // Hacer handling para que el proxy sepa que termino
    if(pop3_ptr->response.current_command == CMD_QUIT){
        return DONE;
    }

    if (pop3_ptr->response.end_string_len != 0) {
        size_t max_size;
        uint8_t * ptr = buffer_write_ptr(pop3_ptr->response.write_buffer, &max_size);
        memcpy(ptr, pop3_ptr->response.end_string, pop3_ptr->response.end_string_len);
        buffer_write_adv(pop3_ptr->response.write_buffer, pop3_ptr->response.end_string_len);
        pop3_ptr->response.end_string_len = 0;
        pop3_ptr->response.end_string = NULL;
        return RESPONSE;
    }

    pop3_ptr->response.is_done = false;
    if(is_empty(pop3_ptr->commands_left)) {
        if(selector_set_interest_key(key, OP_READ) != SELECTOR_SUCCESS 
            || selector_set_interest(key->s, pop3_ptr->origin_fd, OP_NOOP) != SELECTOR_SUCCESS)
            return FAILURE;

        buffer_compact(&pop3_ptr->client_to_origin);
        return REQUEST;
    }

    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || 
        selector_set_interest(key->s, pop3_ptr->origin_fd, OP_WRITE) != SELECTOR_SUCCESS)
        return FAILURE;

    return REQUEST;
}

static int capa_read(struct selector_key* key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    size_t max_size;
    uint8_t* ptr = buffer_write_ptr(&pop3_ptr->origin_to_client, &max_size);
    ssize_t read_chars = recv(pop3_ptr->origin_fd, ptr, max_size, 0);
    if (read_chars <= 0) {
        pop3_ptr->error_message.message = "Error reading from origin";
        if (selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
        
        return FAILURE_WITH_MESSAGE;
    }

    if (!pop3_ptr->capa.has_started) {
        pop3_ptr->response.write_buffer = &pop3_ptr->origin_to_client;
        pop3_ptr->response.write_fd = -1;

        pop3_ptr->capa.has_started = true;
        pop3_ptr->response.is_done = false;
        pop3_ptr->capa.has_dot = false;
        pop3_ptr->current_return = CAPA;
        pop3_ptr->response.read_fd = pop3_ptr->origin_fd;
        pop3_ptr->response.end_string_len = 0;
        pop3_ptr->response.end_string = NULL;

        if (ptr[0] == '-') {
            pop3_ptr->capa.end_of_multiline_parser = parser_init(parser_no_classes(), end_of_line_parser_def);
            pop3_ptr->capa.supports_pipelining = true;
        } else {
            pop3_ptr->capa.end_of_multiline_parser = parser_init(parser_no_classes(), end_of_multiline_parser_def);
            pop3_ptr->capa.supports_pipelining = false;
            pop3_ptr->capa.pipelining_parser = parser_init(parser_no_classes(), pipelining_parser_def);
        }
    }

    ssize_t dot_idx = read_chars;
    for(int i = 0; i < read_chars; i++) {
        if(!pop3_ptr->capa.supports_pipelining) {
            const struct parser_event* pipelining_state = parser_feed(pop3_ptr->capa.pipelining_parser, ptr[i]);
            if(pipelining_state->type == STRING_CMP_EQ) {
                pop3_ptr->capa.supports_pipelining = true;
            } else if(pipelining_state->type == STRING_CMP_NEQ) {
                parser_reset(pop3_ptr->capa.pipelining_parser);
            }
        }

        const struct parser_event* end_state = parser_feed(pop3_ptr->capa.end_of_multiline_parser, ptr[i]);
        
        //\r\n.\r\n
        if(end_state->type == STRING_CMP_EQ) {
            if(!pop3_ptr->capa.supports_pipelining) {
                pop3_ptr->response.end_string = "PIPELINING\r\n.\r\n";
                pop3_ptr->response.end_string_len = 15;
            } else{
                pop3_ptr->response.end_string = END_STRING;
                pop3_ptr->response.end_string_len = 3;
            }

            if(selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS
                || selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
                return FAILURE;
            
            pop3_ptr->response.is_done = true;
            pop3_ptr->capa.has_started = false;
            parser_destroy(pop3_ptr->capa.end_of_multiline_parser);
            pop3_ptr->capa.end_of_multiline_parser = NULL;
            buffer_write_adv(&pop3_ptr->origin_to_client, dot_idx);
            return RESPONSE;
        } else if(end_state->type == STRING_CMP_NEQ) {
            parser_reset(pop3_ptr->capa.end_of_multiline_parser);
            if (ptr[i] == '\r')
                parser_feed(pop3_ptr->capa.end_of_multiline_parser, '\r');
        } else if (ptr[i] == '.') {
            dot_idx = i;
            pop3_ptr->capa.has_dot = true;
        } else if (pop3_ptr->capa.has_dot && ptr[i] == '\r' && dot_idx == read_chars) {
            dot_idx = i;
        }
    }

    buffer_write_adv(&pop3_ptr->origin_to_client, dot_idx);  
    
    if (buffer_can_write(&pop3_ptr->origin_to_client))  
        return CAPA;
    
    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || 
        selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
        return FAILURE;

    return RESPONSE;
}

static int transform_failure(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    buffer_reset(&pop3_ptr->origin_to_client);
    if (pop3_ptr->response.is_done) {
        pop3_ptr->response.end_string = "-ERR Transform failed\r\n";
        pop3_ptr->response.end_string_len = 23;
        return RESPONSE;
    }

    if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || 
        selector_set_interest(key->s, pop3_ptr->origin_fd, OP_READ) != SELECTOR_SUCCESS)
        return FAILURE;

    return RESPONSE;
}

static int transform_init(struct selector_key* key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);

    int in[2], out[2];
    if(pipe(in) == -1 || pipe(out) == -1) {
        log(ERROR, "%s\n", "Failed creating pipe, flushing origin...");

        pop3_ptr->transform.write_fd = pop3_ptr->client_fd;
        return TRANSFORM_FAILURE;
    }
    pop3_ptr->transform.write_fd = in[W];
    pop3_ptr->transform.read_fd = out[R];
    pop3_ptr->transform.started_reading = false;
    pop3_ptr->transform.skipped_line = false;
    pop3_ptr->transform.found_end = false;
    pop3_ptr->transform.is_done = false;
    pop3_ptr->transform.was_dot = false;

    const pid_t cmdpid = fork();

    if (cmdpid == -1) {
        log(ERROR, "%s\n", "Failed forking, flushing origin...");
        pop3_ptr->transform.write_fd = pop3_ptr->client_fd;
        return TRANSFORM_FAILURE;
    } else if (cmdpid == 0) {
        int ret = 0;
        close(in[W]);
        close(out[R]);
        dup2(in[R],  STDIN_FILENO);
        close(in[R]);
        dup2(out[W], STDOUT_FILENO);
        close(out[W]);

        
        int error_fd = open(proxy_config->error_file_path, O_WRONLY | O_CREAT | O_APPEND | O_NONBLOCK);
        if (error_fd == -1) {
            perror("Error opening error file");
        } else if (dup2(error_fd, STDERR_FILENO) == -1) {
            perror("Error piping to error file");
        }

        
        for(int i = 3; i < 1024; i++)
            close(i);

        char envp[3][256] = {"POP3_USERNAME=", "POP3FILTER_VERSION=", "POP3_SERVER="};
        
        strcat(envp[0], (char *) pop3_ptr->user);
        strcat(envp[1], VERSION_NUMBER);
        strcat(envp[2], proxy_config->origin_server_address);
        
        char* env_list[] = { envp[0], envp[1], envp[2], NULL };

        if(execle("/bin/sh", "sh", "-c", proxy_config->pop3_filter_command, (char *) NULL, env_list) == -1) {
            perror("Error executing command");
            close(in[R]);
            close(out[W]);
            ret = 1;
        }
        exit(ret);
    } 

    close(in[R]);
    close(out[W]);

    if (selector_fd_set_nio(in[W]) == -1 || selector_fd_set_nio(out[R]) == -1 || 
        selector_register(key->s, in[W], &pop3_handler, OP_NOOP, key->data) != SELECTOR_SUCCESS) {
        close(in[W]);
        close(out[R]);
        pop3_ptr->transform.write_fd = pop3_ptr->client_fd;
        return TRANSFORM_FAILURE;
    }

    pop3_ptr->references++;
    
    if (selector_register(key->s, out[R], &pop3_handler, OP_NOOP, key->data) != SELECTOR_SUCCESS) {
        selector_unregister_fd(key->s, in[W]);
        close(in[W]);
        close(out[R]);
        pop3_ptr->transform.write_fd = pop3_ptr->client_fd;
        return TRANSFORM_FAILURE;
    }
    
    pop3_ptr->references++;
    pop3_ptr->response.write_buffer = &pop3_ptr->transform_buffer;
    buffer_init(&pop3_ptr->transform_buffer, BUFFER_SIZE, pop3_ptr->read_buffer);
    return TRANSFORM;
}

static int transform_write(struct selector_key * key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    size_t max_size;
    uint8_t * ptr;

    pop3_ptr->response.is_done = false;

    if (!pop3_ptr->transform.skipped_line) {
        ptr = buffer_read_ptr(&pop3_ptr->origin_to_client, &max_size);
        struct parser * end_of_line_parser = parser_init(parser_no_classes(), end_of_line_parser_def);
        size_t i;
        for (i = 0; i < max_size; i++) {
            const struct parser_event* state = parser_feed(end_of_line_parser, ptr[i]);
            if(state->type == STRING_CMP_EQ) {
                pop3_ptr->transform.skipped_line = true;
                pop3_ptr->transform.dot_parser = parser_init(parser_no_classes(), dot_parser_def);
                pop3_ptr->transform.end_parser = parser_init(parser_no_classes(), end_of_multiline_parser_def);
                break;
            } else if(state->type == STRING_CMP_NEQ) {
                parser_reset(end_of_line_parser);
            }
        }

        parser_destroy(end_of_line_parser);
        buffer_read_adv(&pop3_ptr->origin_to_client, i);
        
        buffer_compact(&pop3_ptr->origin_to_client);

        if (!pop3_ptr->transform.skipped_line || !buffer_can_read(&pop3_ptr->origin_to_client)) {
            if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS 
                || selector_set_interest(key->s, pop3_ptr->origin_fd, OP_READ) != SELECTOR_SUCCESS)
                return FAILURE;

            return RESPONSE;
        }
    }

    if (!pop3_ptr->transform.found_end) {
        ptr = buffer_read_ptr(&pop3_ptr->origin_to_client, &max_size);
        size_t write_max_size;
        uint8_t * write_ptr = buffer_write_ptr(&pop3_ptr->transform.proxy_to_pipe, &write_max_size);
        if (write_max_size < max_size)
            max_size = write_max_size;

        size_t write_index = 0;

        for (size_t i = 0; i < max_size; i++) {
            const struct parser_event* end_state = parser_feed(pop3_ptr->transform.end_parser, ptr[i]);
            if(end_state->type == STRING_CMP_EQ) {
                parser_destroy(pop3_ptr->transform.end_parser);
                pop3_ptr->transform.end_parser = NULL;
                pop3_ptr->transform.found_end = true;
                break;
            } else if(end_state->type == STRING_CMP_NEQ) {
                parser_reset(pop3_ptr->transform.end_parser);
                if (ptr[i] == '\r')
                    parser_feed(pop3_ptr->transform.end_parser, '\r');
            }

            const struct parser_event* dot_state = parser_feed(pop3_ptr->transform.dot_parser, ptr[i]);
            if(dot_state->type == STRING_CMP_EQ) {
                parser_reset(pop3_ptr->transform.dot_parser);
                pop3_ptr->transform.was_dot = true;
            } else {
                if(dot_state->type == STRING_CMP_NEQ) {
                    parser_reset(pop3_ptr->transform.dot_parser);
                    if (ptr[i] == '\r')
                        parser_feed(pop3_ptr->transform.dot_parser, '\r');
                } else if (pop3_ptr->transform.was_dot) {
                    pop3_ptr->transform.was_dot = false;
                    continue;
                }
                
                pop3_ptr->transform.was_dot = false;
                write_ptr[write_index++] = ptr[i];
            }
        }
        buffer_read_adv(&pop3_ptr->origin_to_client, max_size);
        buffer_write_adv(&pop3_ptr->transform.proxy_to_pipe, write_index);
    }
    
    ptr = buffer_read_ptr(&pop3_ptr->transform.proxy_to_pipe, &max_size); // TODO ver de hacer un mejor manejo de estructuras
    ssize_t bytes_sent = write(pop3_ptr->transform.write_fd, ptr, max_size);
    if (bytes_sent < 0)
        return FAILURE;

    buffer_read_adv(&pop3_ptr->transform.proxy_to_pipe, bytes_sent);
    buffer_compact(&pop3_ptr->transform.proxy_to_pipe);
    
    if (buffer_can_read(&pop3_ptr->transform.proxy_to_pipe))
        return TRANSFORM;

    if (pop3_ptr->transform.found_end) { 
        close(pop3_ptr->transform.write_fd);

        if (selector_unregister_fd(key->s, pop3_ptr->transform.write_fd) != SELECTOR_SUCCESS)
            return FAILURE;

        pop3_ptr->response.write_fd = -1;
        return TRANSFORM;
    }

    if (selector_set_interest(key->s, pop3_ptr->origin_fd, OP_READ) != SELECTOR_SUCCESS ||
        selector_set_interest(key->s, pop3_ptr->transform.read_fd, OP_NOOP) != SELECTOR_SUCCESS ||
        selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS)
        return FAILURE;

    return RESPONSE;
}

static int transform_read(struct selector_key * key) { 
    struct pop3 *pop3_ptr = ATTACHMENT(key);

    size_t max_size;
    uint8_t * ptr;
    if (!pop3_ptr->transform.started_reading) {
        ptr = buffer_write_ptr(pop3_ptr->response.write_buffer, &max_size);
        char *response = "+OK \r\n"; // TODO mandar rta real y pasarlo a #DEFINE
        memcpy(ptr, response, strlen(response));
        buffer_write_adv(pop3_ptr->response.write_buffer, strlen(response));
        pop3_ptr->transform.started_reading = true;
        parser_reset(pop3_ptr->transform.dot_parser);
    }

    ptr = buffer_write_ptr(pop3_ptr->response.write_buffer, &max_size);
    if (max_size <= 1) { // TODO CHEQUEAR ESTO
        if (selector_set_interest_key(key, OP_NOOP) != SELECTOR_SUCCESS || 
            (pop3_ptr->transform.write_fd != -1 && selector_set_interest(key->s, pop3_ptr->transform.write_fd, OP_NOOP) != SELECTOR_SUCCESS) ||
            selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;

        return RESPONSE;
    }

    size_t read_size;
    uint8_t * read_ptr = buffer_write_ptr(&pop3_ptr->transform.pipe_to_proxy, &read_size);
    read_size = (read_size > max_size) ? max_size : read_size;
    
    ssize_t read_chars = read(pop3_ptr->transform.read_fd, read_ptr, read_size / 2);
    if (read_chars < 0) {
        perror("LEER: ");
        return FAILURE;
    }

    buffer_write_adv(&pop3_ptr->transform.pipe_to_proxy, read_chars);
    read_ptr = buffer_read_ptr(&pop3_ptr->transform.pipe_to_proxy, &read_size);
    
    if (read_chars > 0) {
        ssize_t write_idx = 0;

        for (ssize_t i = 0; i < read_chars; i++) {
            const struct parser_event* state = parser_feed(pop3_ptr->transform.dot_parser, read_ptr[i]);
            if(state->type == STRING_CMP_EQ) {
                ptr[write_idx++] = '.';
                parser_reset(pop3_ptr->transform.dot_parser);
            } else if(state->type == STRING_CMP_NEQ) {
                parser_reset(pop3_ptr->transform.dot_parser);
                if (read_ptr[i] == '\r')
                    parser_feed(pop3_ptr->transform.dot_parser, '\r');
            }
            ptr[write_idx++] = read_ptr[i];
        }

        buffer_read_adv(&pop3_ptr->transform.pipe_to_proxy, read_size);
        buffer_write_adv(pop3_ptr->response.write_buffer, write_idx);

        if ((pop3_ptr->response.write_fd != -1 && 
            selector_set_interest(key->s, pop3_ptr->transform.write_fd, OP_NOOP) != SELECTOR_SUCCESS) || 
            selector_set_interest(key->s, pop3_ptr->transform.read_fd, OP_NOOP) != SELECTOR_SUCCESS ||
            selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            return FAILURE;
            
        return RESPONSE;
    }
    
    parser_destroy(pop3_ptr->transform.dot_parser);
    pop3_ptr->transform.dot_parser = NULL;

    close(pop3_ptr->transform.read_fd);
    buffer_read_adv(&pop3_ptr->transform.pipe_to_proxy, read_size);

    pop3_ptr->response.is_done = true;

    if (selector_unregister_fd(key->s, pop3_ptr->transform.read_fd) != SELECTOR_SUCCESS || 
        selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
        return FAILURE;
        
    pop3_ptr->response.end_string = END_STRING;
    pop3_ptr->response.end_string_len = 3;

    return RESPONSE;
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

    current_connections++;    
    if(current_connections == MAX_CONNECTIONS && 
        ((server_4 != -1 && selector_set_interest(key->s, server_4, OP_NOOP) != SELECTOR_SUCCESS) || 
        (server_6 != -1 && selector_set_interest(key->s, server_6, OP_NOOP) != SELECTOR_SUCCESS)) ) {
        
        goto fail;
    }

    return;

fail:
    if (client != -1) {
        close(client);
    }
    log(DEBUG, "%s", "Fail");
    //pop3_destroy(state);
}

static struct pop3* pop3_new(int client_fd) {
    struct pop3* pop3_ptr;
    if (pool == NULL) {
        pop3_ptr = malloc(sizeof(*pop3_ptr));
        init_parsers(pop3_ptr);
        pop3_ptr->commands_left = new_command_queue();
    } else {
        pop3_ptr = pool;
        reset_parsers(pop3_ptr);
        pool = pool->next;
        pop3_ptr->next = 0;
    }

    pop3_ptr->origin_fd = -1;
    pop3_ptr->client_fd = client_fd;
    pop3_ptr->current_res = NULL;
    pop3_ptr->origin_resolution = NULL;
    pop3_ptr->unmatched_len = 0;
    pop3_ptr->client_address_len = sizeof(client_fd);
    pop3_ptr->stm.initial = RESOLVE_ORIGIN;
    pop3_ptr->stm.max_state = FAILURE;
    pop3_ptr->stm.states = handlers;
    pop3_ptr->capa.supports_pipelining = false;
    pop3_ptr->last_activity = time(NULL);
    stm_init(&pop3_ptr->stm);

    buffer_init(&pop3_ptr->client_to_origin, BUFFER_SIZE, pop3_ptr->read_buffer);
    buffer_init(&pop3_ptr->origin_to_client, BUFFER_SIZE, pop3_ptr->write_buffer);
    pop3_ptr->references = 1;

    return pop3_ptr;
}


static void update_last_activity(struct selector_key* key) {
    struct pop3* pop3_ptr = ATTACHMENT(key);
    pop3_ptr->last_activity = time(NULL);
}

static void pop3_timeout(struct selector_key* key) {
    struct pop3 *pop3_ptr = ATTACHMENT(key);
    if(pop3_ptr != NULL && difftime(time(NULL), pop3_ptr->last_activity) >= client_timeout) {
        log(INFO, "%s", "Disconnecting client for inactivity");
        pop3_ptr->error_message.message = "-ERR Disconnected for inactivity.\r\n";
        if(selector_set_interest(key->s, pop3_ptr->client_fd, OP_WRITE) != SELECTOR_SUCCESS)
            pop3_done(key);

        jump(&pop3_ptr->stm, FAILURE_WITH_MESSAGE, key);
    }
}

static void pop3_read(struct selector_key* key) {
    update_last_activity(key);
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_read(stm, key);

    if (FAILURE == st || DONE == st) {
        pop3_done(key);
    }
}

static void pop3_write(struct selector_key* key) {
    update_last_activity(key);
    struct state_machine* stm = &ATTACHMENT(key)->stm;
    const enum pop3_state st = stm_handler_write(stm, key);

    if (FAILURE == st || DONE == st) {
        pop3_done(key);
    }
}

static void pop3_block(struct selector_key* key) {
    update_last_activity(key);
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
    struct pop3* pop3_ptr = ATTACHMENT(key);

    log(DEBUG, "%s", "Client disconnected");
    current_connections--;
    if(current_connections == MAX_CONNECTIONS - 1) {
        if ((server_4 != -1 && selector_set_interest(key->s, server_4, OP_READ) != SELECTOR_SUCCESS) || 
            (server_6 != -1 && selector_set_interest(key->s, server_6, OP_READ) != SELECTOR_SUCCESS)) {
            log(FATAL, "%s", "Unable to resuscribe to passive socket");
        }
    }

    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (selector_unregister_fd(key->s, fds[i]) != SELECTOR_SUCCESS) {
                abort();
            }
            close(fds[i]);
        }
    }

    reset_parsers(pop3_ptr);
    reset_queue(pop3_ptr->commands_left);
}

static void pop3_destroy_(struct pop3* s) {
    log(DEBUG, "%s", "Freeing pop3 client"); 

    for (int i = 0; i < COMMANDS; i++)
        parser_destroy(s->parsers[i]);

    parser_destroy(s->hello_state.hello_parser);
    parser_destroy(s->request.end_of_line_parser);

    if (s->transform.dot_parser != NULL) {
        parser_destroy(s->transform.dot_parser);
        s->transform.dot_parser = NULL;
    }

    if (s->transform.end_parser != NULL) {
        parser_destroy(s->transform.end_parser);
        s->transform.end_parser = NULL;
    }

    if (s->response.end_of_line_parser != NULL) {
        parser_destroy(s->response.end_of_line_parser);
        s->response.end_of_line_parser = NULL;
    }

    if (s->capa.end_of_multiline_parser != NULL) {
        parser_destroy(s->capa.end_of_multiline_parser);
        s->capa.end_of_multiline_parser = NULL;
    }

    if (s->capa.pipelining_parser != NULL) {
        parser_destroy(s->capa.pipelining_parser);
        s->capa.pipelining_parser = NULL;
    }

    queue_destroy(s->commands_left);
    free(s);
}

static void pop3_destroy(struct pop3* s) {
    if (s == NULL) {
    } else if (s->references == 1) {
        if (pool_size < max_pool) {
            s->next = pool;
            pool = s;
            pool_size++;
        } else {
            pop3_destroy_(s);
        }
    } else {
        s->references -= 1;
    }
}

void pop3_pool_destroy(void) {
    struct pop3* next, * s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;
        pop3_destroy_(s);
    }
}