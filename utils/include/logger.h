#ifndef __logger_h_
#define __logger_h_
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* 
*  Macros y funciones simples para log de errores.
*  EL log se hace en forma simple
*  Alternativa: usar syslog para un log mas completo. Ver sección 13.4 del libro de  Stevens
*/

typedef enum {DEBUG=0, INFO, ERROR, FATAL} LOG_LEVEL;

extern LOG_LEVEL current_level;

/**
*  Minimo nivel de log a registrar. Cualquier llamada a log con un nivel mayor a newLevel sera ignorada
**/
void set_log_level(LOG_LEVEL newLevel);

char * level_description(LOG_LEVEL level);

char * get_current_timestamp();

// Debe ser una macro para poder obtener nombre y linea de archivo. 
#define log(level, fmt, ...)   {if(level >= current_level) {\
	FILE * toPrint = ( level >= ERROR ) ? stderr : stdout; \
	\
	if(level <= INFO) \
		fprintf(toPrint, "%s[%s][ %s ]\033[0m\t%s:%d, ", "\033[0;36m", get_current_timestamp(), level_description(level), __FILE__, __LINE__); \
	else \
		fprintf(toPrint, "%s[%s][ %s ]\033[0m\t%s:%d, ", "\033[0;31m", get_current_timestamp(), level_description(level), __FILE__, __LINE__); \
	fprintf(toPrint, fmt, ##__VA_ARGS__); \
	fprintf(toPrint,"\n"); }\
	if ( level==FATAL) exit(1);}
#endif
