#ifndef _SERVER_UTILS_H
#define _SERVER_UTILS_H

#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <logger.h>
#include <stdbool.h>
#include <netutils.h>


#define MAX_PENDING 20

/**
* Crea un socket con las configuraciones indicadas:
*
* @param listen_addr  la dirección en la que escucha el servidor
* @param service      el puerto deseado
*
* @param protocol     el protocolo de transporte (i.e TCP, UDP)
* @param isipv4       si el param listen_addr es ipv4
*
*/
int setup_server_socket(char * listen_addr, int service, unsigned protocol, bool isipv4);

#endif
