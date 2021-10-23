#include "include/main.h"

proxy_configuration_ptr proxy_conf;

int main(int argc, char *argv[]) {
    proxy_conf = malloc(sizeof(struct proxy_configuration_t));
    parse_options(argc, argv, NULL, NULL, NULL, proxy_conf);
}