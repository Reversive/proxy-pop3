// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <queue.h>

command_queue new_command_queue(){
    return calloc(1, sizeof(t_queue));
}

command_node dequeue(command_queue queue) {
    if (is_empty(queue))
        return NULL;

    command_node aux = queue->first;
    queue->first = aux->next;
    queue->size--;
    if (queue->size == 0)
        queue->last = NULL;
    return aux;
}


void enqueue(command_queue queue, command_node node) {
    if (is_empty(queue)) {
        queue->first = node;
        queue->last = node;
    } else {
        queue->last->next = node;
        queue->last = node;
    }
    queue->size++;
}

bool is_empty(command_queue queue) {
    return queue->size == 0;
}

void free_node(command_node node){
    if(node == NULL)
        return;

    free_node(node->next);
    free(node);
}

void queue_destroy(command_queue queue){
    free_node(queue->first);
    free(queue);
}

command_node peek(command_queue queue) {
    return queue->first;
}

void reset_queue(command_queue queue){
    while (!is_empty(queue)) {
        free(dequeue(queue));
    }
}
