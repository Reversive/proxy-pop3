#include <pop3ctl_utils.h>

#define HAS_VALID_ARG(k) ((k) == 'P' || (k) == 't')
enum ERROR_CODES { STATUS_SUCCESS, STATUS_ERROR };

void print_client_version(int argc) {
    if(argc == 2) {
        printf("POP3 proxy Version: %s\n", VERSION_NUMBER);
        exit(STATUS_SUCCESS);
    }
    fprintf(stderr, "Invalid use of -v option.\n");
    exit(STATUS_ERROR);
}

void print_client_usage() {
    printf("./pop3ctl [ POSIX style options ] <admin-server> \n"
           "POSIX style options: \n"
           "\t-h Prints out help and exits. \n"
           "\t-P [ADMIN PORT] Specifies the port where the admin server is located. By default is 9090. \n"
           "\t-t Admin token [REQUIRED] default is empty string \n"
           "\t-v : Prints out the [NOMBRE] protocol version and exits. \n"
           "<admin-server>: Address of admin server.\n");
}

void print_client_help() {
    printf("\n-------------------------- HELP --------------------------\n");
    print_client_usage();
    exit(STATUS_SUCCESS);
}

client_config_ptr init_client_config() {
    client_config_ptr client_config     = malloc(sizeof(*client_config));
    client_config->admin_token          = NULL;
    client_config->admin_server_address = "127.0.0.1";
    client_config->admin_server_port    = 9090;
    return client_config;
}

client_config_ptr parse_client_options(int argc, char *argv[]) {
    client_config_ptr client_config = init_client_config();
    int option;

    while((option = getopt(argc, argv, "hvP:t:")) != -1) {
        switch (option) {
        case 'h':
            print_client_help();
            break;
        case 'P':
            client_config->admin_server_port = atoi(optarg);
            break;
        case 't':
            client_config->admin_token = optarg;
            break; 
        case 'v':
            print_client_version(argc);
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
        fprintf(stderr, "Invalid args, please use: client [POSIX style options] <origin-address>\n");
        exit(STATUS_ERROR);
    }

    int is_invalid_arg = 0;
    for (int index = optind; index < argc-1; index++) {
        printf ("Invalid argument %s\n", argv[index]);
        is_invalid_arg = 1;
    }

    if(is_invalid_arg)
        exit(STATUS_SUCCESS);

    client_config->admin_server_address = argv[optind];
    return client_config;
}