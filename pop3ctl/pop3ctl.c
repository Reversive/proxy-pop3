// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <pop3ctl.h>

typedef struct t_admin_command {
    char def[MAX_COMMAND_LEN];
    char help_str[40];
} t_admin_command;

t_admin_command commands[] = { 
    {"STATS", "get pop3filer stats"},
    {"GET_TIMEOUT", "get pop3filer timeout"},
    {"SET_TIMEOUT", "set pop3filer timeout"},
    {"GET_FILTER_CMD", "get pop3filer filter command"},
    {"SET_FILTER_CMD", "set pop3filer filter command"},
    {"GET_ERROR_FILE", "get pop3filer error file"},
    {"SET_ERROR_FILE", "set pop3filer error file"} 
};

client_config_ptr client_config;

static int get_command_number(const char* cmd);
static void print_help();
static int udpClientSocket(const char *host, const char *service, struct addrinfo **serv_addr);

static int parse_admin_response(t_admin_resp * response, uint8_t * buffer, int buff_len);
static bool cmp_str(uint8_t * str1, uint8_t * str2, uint8_t size);

int main(int argc, char* argv[]) {
    client_config = parse_client_options(argc, argv);

    if(client_config->admin_token == NULL){
        printf("Token is mandatory. Try using -t token\n");
        return -1;
    }

    if(strlen(client_config->admin_token) != 10){
        printf("Token must have exactly 10 characters\n");
        return -1;
    }

    int sockfd;
    char buffer[DGRAM_SIZE];

    // Creating socket file descriptor

    struct addrinfo * servaddr;
    //socklen_t len = sizeof(servaddr);
    sockfd = udpClientSocket(client_config->admin_server_address, client_config->admin_server_port, &servaddr);
    if (sockfd == -1) {
        log(ERROR, "%s", "Error creating socket");
        return -1;
    }

    struct sockaddr_storage fromAddr; // Source address of server
    socklen_t fromAddrLen = sizeof(fromAddr);

    ssize_t n;
    
    int i, j, curr_command, read_chars_in;
    char command[MAX_COMMAND_LEN];
    char req_buff[DGRAM_SIZE] = { 0 };

    memcpy(req_buff, ADMIN_VERSION_STR, 3);
    memcpy(req_buff + 3, client_config->admin_token, 10);
    char* stdin_buffer = NULL;
    size_t stdin_len = 0;

    while (1) {
        if ((read_chars_in = getline(&stdin_buffer, &stdin_len, stdin)) < 0) {
            perror("Error reading from stdin");
        }

        for (i = 0; i < read_chars_in && i < MAX_COMMAND_LEN; i++) {
            if (stdin_buffer[i] == ' ') {
                i++;
                break;
            }
            command[i] = toupper(stdin_buffer[i]);
        }

        command[i-1] = 0;
        if (strcmp("HELP", command) == 0){
            print_help();
            continue;
        }

        curr_command = get_command_number(command);
        if (curr_command == -1) {
            printf("Comando invalido\n");
            continue;
        }

        req_buff[13] = (char) curr_command;
        for (j = 14; i < read_chars_in; i++, j++)
            req_buff[j] = stdin_buffer[i];

        memcpy(req_buff + j, ADMIN_LINE_END_STR, ADMIN_LINE_END_LEN);
        j += ADMIN_LINE_END_LEN;


        if (sendto(sockfd, (const char*) req_buff, j, MSG_CONFIRM, servaddr->ai_addr, servaddr->ai_addrlen) < 0){
            perror("Error sending request to proxy");
            return -1;
        }

        n = recvfrom(sockfd, (char *) buffer, MAX_LINE, MSG_WAITALL, (struct sockaddr *) &fromAddr, &fromAddrLen);

        if(n == -1){
            perror("Error using recv");
            return -1;
        }

        t_admin_resp response;
        if (parse_admin_response(&response, (uint8_t *) buffer, n) != 0) {
            printf("Invalid response from origin");
            continue;
        }

        if(response.status == 0){
            printf("+OK\n%s\n", (char*) response.data);
        } else {
            printf("-ERROR: %s\n", (char*) response.data);
        }
    }
    return 0;
}

static int parse_admin_response(t_admin_resp * response, uint8_t * buffer, int buff_len) {
    if (buff_len < VERSION_SIZE + 1) {

        printf("len\n");
        return 1;
    }
    
    if (!cmp_str(buffer, ADMIN_VERSION, VERSION_SIZE)) {
        printf("Vers\n");
        return 1;
    }
    
    memcpy(response->version, buffer, VERSION_SIZE);
    buffer += VERSION_SIZE;

    if (*buffer >= INTERNAL_ERROR) {
        printf("Buff %d\n", *buffer);
        return 1;
    }
    
    response->status =  *buffer;
    buffer = buffer + 1;

    memcpy(response->data, buffer, buff_len - VERSION_SIZE - ADMIN_LINE_END_LEN - 1);
    response->data[buff_len - VERSION_SIZE - ADMIN_LINE_END_LEN - 1] = '\0';

    buffer += buff_len - VERSION_SIZE - ADMIN_LINE_END_LEN - 1;
    if (!cmp_str(buffer, ADMIN_LINE_END, ADMIN_LINE_END_LEN)) {
        printf("END\n");
        return 1;
    }

    return 0;
}


static bool cmp_str(uint8_t * str1, uint8_t * str2, uint8_t size) {
	for (int i = 0; i < size; i++) {
        if (str1[i] != str2[i]) 
            return false;
    }
    
    return true;
}


static int get_command_number(const char* cmd) {
    for (int i = 0; i < COMMAND_SIZE; i++) {
        if (strcmp(cmd, commands[i].def) == 0) {
            return i;
        }
    }
    return -1;
}

static void print_help(){
    printf("Proxy Management Protocol valid commands:\n");
    for (int i = 0; i<COMMAND_SIZE; i++){
        printf("- %s ", commands[i].def);
        printf("%s\n", commands[i].help_str);
    }
}

static int udpClientSocket(const char *host, const char *service, struct addrinfo **serv_addr) {
	struct addrinfo addr_criteria;                   // Criteria for address match
	memset(&addr_criteria, 0, sizeof(addr_criteria)); // Zero out structure
	addr_criteria.ai_family = AF_UNSPEC;             // v4 or v6 is OK
	addr_criteria.ai_socktype = SOCK_DGRAM;        
	addr_criteria.ai_protocol = IPPROTO_UDP;         

	int rtnVal = getaddrinfo(host, service, &addr_criteria, serv_addr);
	if (rtnVal != 0) {
		log(ERROR, "getaddrinfo() failed %s", gai_strerror(rtnVal))
		return -1;
	}

	int sock = -1;
	for (struct addrinfo *addr = *serv_addr; addr != NULL; addr = addr->ai_next) {
		sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		if (sock >= 0) {
            break;
		} 
	}

	return sock;
}

