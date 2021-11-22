#ifndef ADMIN_UTILS_H
#define ADMIN_UTILS_H

#include <stdint.h>

#define ADMIN_VERSION ((uint8_t *) "0.0")
#define ADMIN_TOKEN ((uint8_t *)"SECRETPROX")
#define ADMIN_TOKEN_STR "SECRETPROX"
#define ADMIN_VERSION_STR "0.0"

#define DGRAM_SIZE 512
#define HEADER_SIZE 14
#define VERSION_SIZE 3
#define TOKEN_SIZE 10

#define DATA_SIZE (DGRAM_SIZE - HEADER_SIZE)

typedef struct t_admin_req {
    uint8_t     version[VERSION_SIZE];
    uint8_t     token[TOKEN_SIZE];
    uint8_t     command;
    uint8_t     data[DATA_SIZE];
} t_admin_req;

typedef struct t_admin_resp {
    uint8_t     version[VERSION_SIZE];
    uint8_t     status;
    uint8_t     data[DGRAM_SIZE - 4];
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
    UNSUPPORTED_VERSION,
    INVALID_ARGS,
    UNAUTHORIZED,
    INTERNAL_ERROR
};

#define LAST_COMMAND SET_ERROR_FILE
#define COMMAND_SIZE (LAST_COMMAND + 1)
#define MAX_COMMAND_LEN 15

#endif