include makefile.inc

SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
rm       = rm -rf


all:$(SOURCES)
	$(GCC) $(CFLAGS) -I./include $(SOURCES)


%.o : %.c
	$(GCC) $(CFLAGS) -c $< -o $@

clean:
	@$(rm) $(OBJECTS)