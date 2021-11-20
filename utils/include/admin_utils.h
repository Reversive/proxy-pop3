#ifndef ADMIN_UTILS_H
#define ADMIN_UTILS_H

#define ADMIN_VERSION ((uint8_t *) "0.0")
#define ADMIN_TOKEN ((uint8_t *)"SECRETPROX")

typedef struct t_admin_req {
    uint8_t     version[3];
    uint8_t     token[10];
    uint8_t     command;
    uint8_t *   data;
} t_admin_req;

typedef struct t_admin_resp {
    uint8_t     version[3];
    uint8_t     status;
    uint8_t *   data;
} t_admin_resp;

enum admin_commands {
    STATS = 0,
    GET_TIMEOUT,
    SET_TIMEOUT,
    GET_FILTER_CMD,
    SET_FILTER_CMD,
    GET_ERROR_FILE,
    SET_ERROR_FILE  
};

enum response_stats {
    OK = 0,
    UNSOPPORTED_COMMAND,
    INVALID_ARGS,
    UNAUTHORIZED,
    INTERNAL_ERROR
};

#define LAST_COMMAND SET_ERROR_FILE
#define COMMAND_SIZE LAST_COMMAND + 1

#endif