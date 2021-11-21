#include <logger.h>

LOG_LEVEL current_level = DEBUG;

char * get_current_timestamp() {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    static char buffer[20];
    sprintf(buffer, "%d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buffer;
}

void set_log_level(LOG_LEVEL newLevel) {
	if ( newLevel >= DEBUG && newLevel <= FATAL )
	   current_level = newLevel;
}

char * level_description(LOG_LEVEL level) {
    static char * description[] = {"DEBUG", "INFO", "ERROR", "FATAL"};
    if (level < DEBUG || level > FATAL)
        return "";
    return description[level];
}
