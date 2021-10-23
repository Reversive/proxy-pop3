#ifndef PARSE_OPTIONS_H
#define PARSE_OPTIONS_H
#include <stdio.h> /* para printf */
#include <stdlib.h> /* para exit */
#define _GNU_SOURCE
#include <getopt.h> /*para getopt_long*/ 
#include "data_structures.h"

void parse_options( int argc, char *argv[], void * proxy_data, 
                    void * proxy_admin_data, void * origin_server_data,
                    proxy_configuration_ptr proxy_config);

#endif