#ifndef PARSE_OPTIONS_H
#define PARSE_OPTIONS_H
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <getopt.h>
#include "data_structures.h"
#include <ctype.h>

proxy_configuration_ptr parse_options(int argc, char *argv[]);

#endif