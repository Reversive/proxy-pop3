CFLAGS = -c -g --std=c11 -pedantic -fsanitize=address -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200809L -pthread

LFLAGS = -g --std=c11 -pedantic -fsanitize=address  -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200809L -lpthread -pthread
