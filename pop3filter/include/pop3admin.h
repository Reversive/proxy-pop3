#ifndef _POP3_ADMIN_H
#define _POP3_ADMIN_H

#include <logger.h>
#include <selector.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <admin_utils.h>


#define BUFFSIZE 1024

void admin_parse(struct selector_key* key);

#endif