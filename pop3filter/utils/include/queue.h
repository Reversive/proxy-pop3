#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct t_node {
    int command;
    uint8_t * buff;
    uint8_t command_len;
    bool has_args;
    struct t_node * next;
} t_node;

typedef struct t_queue {
    uint16_t size;
    struct t_node * first;
    struct t_node * last;
} t_queue;

typedef struct t_queue * command_queue;

typedef struct t_node * command_node;

command_queue new_command_queue();

command_node dequeue(command_queue queue);

command_node peek(command_queue queue);

void enqueue(command_queue queue, command_node node);

bool is_empty(command_queue queue);

void free_node(command_node node);

void destroy(command_queue queue);

