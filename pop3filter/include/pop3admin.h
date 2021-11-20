#ifndef _POP3_ADMIN_H
#define _POP3_ADMIN_H

#include <logger.h>
#include <selector.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>


#define BUFFSIZE 1024

extern int admin_4;
extern int admin_6;
void admin_parse(struct selector_key* key);

#endif