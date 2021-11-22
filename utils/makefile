include makefile.inc

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
rm       = rm -rf

all:$(SOURCES)
	$(CC) $(CFLAGS) -I./include $(SOURCES)

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@$(rm) $(OBJECTS)