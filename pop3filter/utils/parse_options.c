#include "include/parse_options.h"

#define VERSION_NUMBER "1.0"
#define HAS_VALID_ARG(k) ((k) == 'e' || (k) == 'l' || (k) == 'L' || (k) == 'o' || (k) == 'p' || (k) == 'P' || (k) == 't')
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

proxy_configuration_ptr init_proxy_config() {
    proxy_configuration_ptr proxy_config    = malloc(sizeof(*proxy_config));
    proxy_config->error_file_path           = "/dev/null";
    proxy_config->pop3_listen_address       = "0.0.0.0";
    proxy_config->admin_listen_address      = "127.0.0.1";
    proxy_config->pop3_listen_port          = 1110;
    proxy_config->admin_listen_port         = 9090;
    proxy_config->origin_server_port        = 110;
    return proxy_config;
}
proxy_configuration_ptr parse_options(int argc, char *argv[]) {
    proxy_configuration_ptr proxy_config = init_proxy_config();
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
            proxy_config->admin_listen_port = atoi(optarg);
            break;
        case 'p':
            proxy_config->pop3_listen_port = atoi(optarg);
            break;
        case 'P':
            proxy_config->origin_server_port = atoi(optarg);
            break;
        case 't':
            proxy_config->pop3_filter_command = optarg;
            break; 
        case 'v':
            print_proxy_version(argc);
            break;
        case '?':
            if(HAS_VALID_ARG(optopt)) {
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            } else if(isprint(optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            } else {
                fprintf (stderr,"Unknown option character `\\x%x'.\n", optopt);
            }
            break;

        default:
            fprintf(stderr, "Invalid options, use -h to print help\n");
            exit(STATUS_ERROR);
            break;
        }
    }

    if(argc - optind != 1) {
        fprintf(stderr, "Invalid args, please use: pop3filter [POSIX style options] <origin-address>\n");
        exit(STATUS_ERROR);
    }

    int is_invalid_arg = 0;
    for (int index = optind; index < argc-1; index++) {
        printf ("Invalid argument %s\n", argv[index]);
        is_invalid_arg = 1;
    }

    if(is_invalid_arg)
        exit(STATUS_SUCCESS);

    proxy_config->origin_server_address = argv[optind];
    return proxy_config;
}