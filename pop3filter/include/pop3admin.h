#ifndef _POP3_ADMIN_H
#define _POP3_ADMIN_H

#include <logger.h>
#include <selector.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <admin_utils.h>
#include <data_structures.h>

#define BUFFSIZE 1024

void admin_parse(struct selector_key* key);

extern size_t historic_connections;
extern size_t current_connections;
extern size_t transferred_bytes;
extern float  client_timeout;

extern proxy_configuration_ptr proxy_config;

#endif