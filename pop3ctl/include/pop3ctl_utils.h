#ifndef POP3CTL_UTILS_H
#define POP3CTL_UTILS_H

#define VERSION_NUMBER "0.0"

#include <pop3ctl.h>
#include <getopt.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void print_client_version(int argc);
void print_client_usage();
void print_client_help();

client_config_ptr init_client_config();
client_config_ptr parse_client_options(int argc, char *argv[]);


#endif