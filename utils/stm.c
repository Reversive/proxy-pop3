// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 * stm.c - pequeño motor de maquina de estados donde los eventos son los
 *         del selector.c
 */
#include <stdlib.h>
#include <stm.h>
#define error -1
#define N(x) (sizeof(x)/sizeof((x)[0]))

void stm_init(struct state_machine * stm) {
    int i;

    // verificamos que los estados son correlativos, y que están bien asignados.
    for (i = 0 ; i <= stm->max_state; i++) {
        if (i != stm->states[i].state) {
            abort();
        }
    }

    if (stm->initial < stm->max_state) {
        stm->current = NULL;
    } else {
        abort();
    }
}

inline static void handle_first(struct state_machine * stm, key_ptr key) {
    if (stm->current == NULL) {
        stm->current = stm->states + stm->initial;
        if (stm->current->on_arrival != NULL) {
            stm->current->on_arrival(key);
        }
    }
}

void jump(struct state_machine * stm, int next, key_ptr key) {
    if (next > stm->max_state) {
        abort();
    }

    if (next != error && stm->current != stm->states + next) {
        if(stm->current != NULL && stm->current->on_departure != NULL) {
            stm->current->on_departure(key);
        }

        stm->current = stm->states + next;

        if (stm->current->on_arrival != NULL) {
            stm->current->on_arrival(key);
        }
    }

}

int stm_handler_read(struct state_machine * stm, key_ptr key) {
    handle_first(stm, key);

    if (stm->current->on_read_ready == 0) {
        abort();
    }

    const int ret = stm->current->on_read_ready(key);

    jump(stm, ret, key);
    return ret;
}

int stm_handler_write(struct state_machine * stm, key_ptr key) {
    handle_first(stm, key);

    if (stm->current->on_write_ready == 0) {
        abort();
    }

    const int ret = stm->current->on_write_ready(key);
    jump(stm, ret, key);

    return ret;
}

int stm_handler_block(struct state_machine * stm, key_ptr key) {
    handle_first(stm, key);

    if(stm->current->on_block_ready == 0) {
        abort();
    }

    const int ret = stm->current->on_block_ready(key);
    jump(stm, ret, key);

    return ret;
}