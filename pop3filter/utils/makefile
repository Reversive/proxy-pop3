include makefile.inc

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
rm       = rm -rf


all:$(SOURCES)
	$(GCC) $(CFLAGS) $(SOURCES)


%.o : %.c
	$(GCC) $(CFLAGS) -I./include -c $< -o $@

clean:
	@$(rm) $(OBJECTS)