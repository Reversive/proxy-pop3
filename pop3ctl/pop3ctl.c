#include <pop3ctl.h>

client_config_ptr client_config;

int main(int argc, char * argv[]) {
    client_config = parse_client_options(argc, argv);
    printf("Client connect to %s:%d using token %s\n", 
        client_config->admin_server_address, client_config->admin_server_port, client_config->admin_token);
    
    int sockfd;
    char buffer[MAX_LINE];
    char *hello = "Hello from client\n";
    struct sockaddr_in     servaddr;

    printf("Trying to create socket\n");
   
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
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

    sendto(sockfd, (const char *) hello, strlen(hello),
        MSG_CONFIRM, (const struct sockaddr *) &servaddr, 
            sizeof(servaddr));
    printf("Hello message sent.\n");
           
    n = recvfrom(sockfd, (char *) buffer, MAX_LINE, 
                MSG_WAITALL, (struct sockaddr *) &servaddr,
                &len);

    buffer[n] = '\0';
    printf("Server : %s\n", buffer);

    return 0;
}