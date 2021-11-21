#include <pop3ctl.h>


char* commands[] = { "STATS","GET_TIMEOUT","SET_TIMEOUT","GET_FILTER_CMD","SET_FILTER_CMD","GET_ERROR_FILE","SET_ERROR_FILE" };

client_config_ptr client_config;

static int get_command_number(const char* cmd);

int main(int argc, char* argv[]) {
    client_config = parse_client_options(argc, argv);
    printf("Client connect to %s:%d using token %s\n",
        client_config->admin_server_address, client_config->admin_server_port, client_config->admin_token);

    int sockfd;
    char buffer[MAX_LINE];
    struct sockaddr_in     servaddr;

    printf("Trying to create socket\n");

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed\n");
        exit(EXIT_FAILURE);
    }

    printf("socket %d\n", sockfd);

    memset(&servaddr, 0, sizeof(servaddr));
    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(client_config->admin_server_port);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    ssize_t n;
    socklen_t len = sizeof(servaddr);

    int i, j, curr_command, read_chars_in;
    char command[MAX_COMMAND_LEN];
    char data[DATA_SIZE];
    char req_buff[DGRAM_SIZE] = { 0 };

    memcpy(req_buff, ADMIN_VERSION_STR, 3);
    memcpy(req_buff + 3, ADMIN_TOKEN_STR, 10);
    char* stdin_buffer = NULL;
    size_t stdin_len = 0;

    while (1) {

        if ((read_chars_in = getline(&stdin_buffer, &stdin_len, stdin)) < 0) {
            perror("Error reading from stdin");
        }

        for (i = 0; i < read_chars_in && i < MAX_COMMAND_LEN; i++) {
            if (stdin_buffer[i] == ' ') {
                break;
            }
            command[i] = toupper(stdin_buffer[i]);
        }

        command[i-1] = 0;
        curr_command = get_command_number(command);

        if (curr_command == -1) {
            perror("Comando invalido");
            req_buff[13]=0;
            continue;
        }

        req_buff[13] = curr_command + '0';
        if (i++ < read_chars_in) {
            for (j = 14; i < read_chars_in; i++, j++)
                req_buff[j] = stdin_buffer[i];
            data[j] = 0;
            strcat(req_buff, data);
        }
        else {
            req_buff[14] = 0;
        }

        sendto(sockfd, (const char*)req_buff, strlen(req_buff), MSG_CONFIRM, (const struct sockaddr*)&servaddr, sizeof(servaddr));

        printf("%s\n", req_buff);
        req_buff[13] = 0;

        n = recvfrom(sockfd, (char*)buffer, MAX_LINE, MSG_WAITALL, (struct sockaddr*)&servaddr, &len);

        buffer[n] = '\0';
        printf("Server : %s\n", buffer);
    }
    free(req_buff);
    return 0;
}

static int get_command_number(const char* cmd) {
    for (int i = 0; i < COMMAND_SIZE; i++) {
        if (strcmp(cmd, commands[i]) == 0) {
            return i;
        }
    }
    return -1;
}