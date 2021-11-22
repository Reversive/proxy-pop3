#ifndef PARSE_OPTIONS_H
#define PARSE_OPTIONS_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <data_structures.h>
#include <ctype.h>
#include <logger.h>

proxy_configuration_ptr parse_options(int argc, char *argv[]);

#endif