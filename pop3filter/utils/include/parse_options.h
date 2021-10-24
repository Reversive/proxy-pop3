#ifndef PARSE_OPTIONS_H
#define PARSE_OPTIONS_H
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <getopt.h>
#include "data_structures.h"

void parse_options( int argc, char *argv[], void * proxy_data, 
                    void * proxy_admin_data, void * origin_server_data,
                    proxy_configuration_ptr proxy_config);

#endif