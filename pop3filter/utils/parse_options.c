#include "include/parse_options.h"

#define VERSION_NUMBER "1.0"

enum ERROR_CODES { STATUS_SUCCESS, STATUS_ERROR };

void print_proxy_version(int argc) {
    if(argc == 2) {
        printf("POP3 Version: %s\n", VERSION_NUMBER);
        exit(STATUS_SUCCESS);
    }
    fprintf(stderr, "Invalid use of -v option.\n");
    exit(STATUS_ERROR);
}

void print_usage() {
    printf("./pop3filter [ POSIX style options ] <origin-server> \n"
           "POSIX style options: \n"
           "\t-e [ERROR FILE]: Specifies the file where to redirect stderr. By default the stderr is redirected to /dev/null. \n"
           "\t-h Prints out help and exits. \n"
           "\t-l [POP3 LISTEN ADDRESS] Specifies the address where the POP3 proxy will listen to. \n"
           "\t-L [MANAGEMENT ADDRESS] Specifies the address where the management service will listen to. \n"
           "\t-o [MANAGEMENT PORT]: Specifies the port where the management server is located. By default is 9090. \n"
           "\t-p [LOCAL PORT] Specifies the port where to listen for incoming POP3 connections. By default is 1110. \n"
           "\t-P [ORIGIN PORT] Specifies the port where the POP3 server is located. By default is 110. \n"
           "\t-t [FILTER COMMAND]: Command used for external transformations. By default applies no transformations. \n"
           "\t-v : Prints out the POP3 proxy version and exits. \n"
           "<origin-server>: Address of POP3 origin server.\n");
}

void print_help() {
    printf("\n-------------------------- HELP --------------------------\n");
    print_usage();
    exit(STATUS_SUCCESS);
}

void parse_options( int argc, char *argv[], void * proxy_data, 
                    void * proxy_admin_data, void * origin_server_data,
                    proxy_configuration_ptr proxy_config) {
    int option;
    while((option = getopt(argc, argv, "e:hl:L:o:p:P:t:v")) != -1) {
        switch (option) {
        case 'e':
            proxy_config->error_file_path = optarg;
            break;
        case 'h':
            print_help();
            break;
        case 'l':
            proxy_config->pop3_listen_address = optarg;
            break;
        case 'L':
            proxy_config->admin_listen_address = optarg;
            break;
        case 'o':
            break;
        case 'p':
            break;
        case 'P':
            break;
        case 't':
            proxy_config->pop3_filter_command = optarg;
            break; 
        case 'v':
            print_proxy_version(argc);
            break;
        default:
            fprintf(stderr, "Invalid options, use -h to print help\n");
            exit(STATUS_ERROR);
            break;
        }
    }
}