all: pop3filter pop3ctl

pop3filter:
	cd pop3filter; make all

pop3ctl:
	cd pop3ctl; make all

clean:
	cd pop3filter; make clean
	cd pop3ctl; make clean

.PHONY: all clean pop3filter pop3ctl
