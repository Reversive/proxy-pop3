GCC=gcc
CFLAGS = -c -g --std=c11 -fsanitize=address -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200809L -pthread

LINKER=gcc
LFLAGS = -g --std=c11 -fsanitize=address -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200809L -lpthread -pthread
