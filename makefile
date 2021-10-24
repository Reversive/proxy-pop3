all: pop3filter

pop3filter:
	cd pop3filter; make all

clean:
	cd pop3filter; make clean

.PHONY: all clean pop3filter
