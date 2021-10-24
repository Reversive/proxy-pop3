include makefile.inc

BINARY	= pop3filter
SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)
rm      = rm -rf

all: utils compile link

compile:$(SOURCES)
	$(GCC) $(CFLAGS) -I./include $(SOURCES)

link:$(OBJECTS)
	$(LINKER) $(LFLAGS) $(OBJECTS) ./utils/*.o -o $(BINARY).out

utils:
	cd utils; make all

%.o: %.c
	$(GCC) $(GCCFLAGS) -I./include -c $< -o $@

%.out : %.o
	$(LINKER) $(LFLAGS) $< -o $@

clean:
	cd utils; make clean
	@${rm} ${OBJECTS} 
	@${rm} ${BINARY}.out

.PHONY: all clean utils link compile