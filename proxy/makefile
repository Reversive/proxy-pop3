include makefile.inc

BINARY=pop3proxy
SOURCES=$(wildcard *.c)
OBJECTS=$(SOURCES:.c=.o)
rm       = rm -rf

all: compile link

compile:$(SOURCES)
		$(GCC) $(CFLAGS) -I./include $(SOURCES) 

link:$(OBJECTS)
	 $(LINKER) $(LFLAGS) $(OBJECTS) -o $(BINARY).out

%.o: %.c
	$(GCC) $(GCCFLAGS) -I./include -c $< -o $@

%.out : %.o
	$(LINKER) $(LFLAGS) $< -o $@

clean:
	@${rm} ${OBJECTS}
	@${rm} ${BINARY}.out

.PHONY: all clean